//! `summary_cache` — Function summary cache for symbolic execution.
//!
//! Function summaries capture the input → output relation, side effects, and
//! preconditions of a function, allowing the symbolic executor to inline
//! a summary instead of re-analysing the function body on every call.
//!
//! The cache uses a fingerprint-based lookup so that structurally identical
//! call sites share their summary.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{SymExpr, SymType};

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SummaryError {
    #[error("summary not found for function {0:#x}")]
    NotFound(u64),
    #[error("summary application failed: {0}")]
    ApplicationError(String),
    #[error("precondition violated for function {func:#x}: {detail}")]
    PreconditionViolated { func: u64, detail: String },
    #[error("summary fingerprint collision at {0:#x}")]
    FingerprintCollision(u64),
}

// ─── ArgEffect ────────────────────────────────────────────────────────────────

/// Describes what a function does to one of its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgEffect {
    /// Argument is read only; no side effects on it.
    ReadOnly,
    /// Argument pointer target is overwritten with a symbolic value.
    Written,
    /// Argument pointer target is freed.
    Freed,
    /// Argument is passed to a sub-function without further tracking.
    Forwarded,
    /// Custom effect described symbolically.
    CustomExpr(SymExpr),
}

// ─── SideEffect ───────────────────────────────────────────────────────────────

/// A concrete side effect produced by a summarised function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SideEffect {
    /// The function writes `value` to memory at `addr`.
    MemoryWrite { addr: SymExpr, value: SymExpr },
    /// The function reads from memory at `addr`.
    MemoryRead { addr: SymExpr },
    /// The function calls `target` with `args`.
    CallTo { target: u64, args: Vec<SymExpr> },
    /// The function modifies the register named `name`.
    ModifiesRegister { name: String, new_value: SymExpr },
    /// The function raises an exception / calls exit.
    Terminates,
    /// Custom user-defined side effect.
    Custom(String),
}

// ─── Precondition ─────────────────────────────────────────────────────────────

/// A precondition that must hold before the summary is applicable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Precondition {
    /// Symbolic expression that must be satisfiable.
    pub constraint: SymExpr,
    /// Human-readable description.
    pub description: String,
}

impl Precondition {
    #[must_use]
    pub fn new(constraint: SymExpr, description: impl Into<String>) -> Self {
        Self {
            constraint,
            description: description.into(),
        }
    }

    /// Check whether this precondition is trivially satisfied (evaluates to
    /// `ConstBool(true)` after simplification).
    #[must_use]
    pub fn is_trivially_satisfied(&self) -> bool {
        let s = self.constraint.simplify();
        s == SymExpr::ConstBool(true)
    }
}

// ─── OutputRelation ───────────────────────────────────────────────────────────

/// Maps input argument symbolic expressions to the output (return value).
///
/// The relation is represented as a symbolic expression in terms of named
/// argument variables `arg0`, `arg1`, ..., `argN`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputRelation {
    /// Expression for the return value in terms of argument variables.
    pub return_value: SymExpr,
    /// Mapping from `argN` variable name to the actual argument position.
    pub arg_map: HashMap<String, usize>,
    /// Width of the return value in bits.
    pub return_width: u32,
}

impl OutputRelation {
    /// Create a new output relation with a return expression.
    #[must_use]
    pub fn new(return_value: SymExpr, return_width: u32) -> Self {
        Self {
            return_value,
            arg_map: HashMap::new(),
            return_width,
        }
    }

    /// Create a relation that returns the identity of argument `idx`.
    #[must_use]
    pub fn identity(arg_idx: usize, width: u32) -> Self {
        let name = format!("arg{arg_idx}");
        let expr = SymExpr::var(name.clone(), SymType::BitVec(width));
        let mut rel = Self::new(expr, width);
        rel.arg_map.insert(name, arg_idx);
        rel
    }

    /// Create a relation that always returns a constant.
    #[must_use]
    pub fn constant(val: u64, width: u32) -> Self {
        Self::new(SymExpr::bv(val, width), width)
    }

    /// Instantiate the relation: substitute argument variables with `args`.
    ///
    /// Returns the return value expression with arguments substituted.
    #[must_use]
    pub fn instantiate(&self, args: &[SymExpr]) -> SymExpr {
        let mut result = self.return_value.clone();
        for (name, &idx) in &self.arg_map {
            if let Some(arg) = args.get(idx) {
                result = substitute_expr(&result, name, arg);
            }
        }
        result
    }
}

// ─── FunctionSummary ──────────────────────────────────────────────────────────

/// Complete summary of a function's symbolic behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    /// Address of the summarised function.
    pub func_addr: u64,
    /// Optional human-readable function name.
    pub name: Option<String>,
    /// Input → output relation (return value).
    pub output_relation: OutputRelation,
    /// Known side effects.
    pub side_effects: Vec<SideEffect>,
    /// Preconditions (caller must ensure these hold before the call).
    pub preconditions: Vec<Precondition>,
    /// Per-argument effects.
    pub arg_effects: Vec<ArgEffect>,
    /// Whether this function is a no-op (can be skipped entirely).
    pub is_nop: bool,
    /// Whether this function is known to never return (e.g. `exit`).
    pub never_returns: bool,
    /// Whether this is a stub (summary was generated automatically).
    pub is_stub: bool,
    /// Fingerprint used for cache lookup.
    pub fingerprint: SummaryFingerprint,
}

impl FunctionSummary {
    /// Create a minimal summary that returns a fresh symbolic variable.
    #[must_use]
    pub fn opaque(func_addr: u64, name: impl Into<String>) -> Self {
        let name_str = name.into();
        let ret_var = SymExpr::var(format!("ret_{func_addr:#x}"), SymType::BitVec(64));
        Self {
            func_addr,
            name: Some(name_str.clone()),
            output_relation: OutputRelation::new(ret_var, 64),
            side_effects: Vec::new(),
            preconditions: Vec::new(),
            arg_effects: Vec::new(),
            is_nop: false,
            never_returns: false,
            is_stub: true,
            fingerprint: SummaryFingerprint::from_addr_name(func_addr, &name_str),
        }
    }

    /// Create a summary for a function that returns 0 (e.g. `memset`-like).
    #[must_use]
    pub fn returns_zero(func_addr: u64, name: impl Into<String>) -> Self {
        let name_str = name.into();
        Self {
            func_addr,
            name: Some(name_str.clone()),
            output_relation: OutputRelation::constant(0, 64),
            side_effects: Vec::new(),
            preconditions: Vec::new(),
            arg_effects: Vec::new(),
            is_nop: false,
            never_returns: false,
            is_stub: false,
            fingerprint: SummaryFingerprint::from_addr_name(func_addr, &name_str),
        }
    }

    /// Create a summary for a function that is a no-op.
    #[must_use]
    pub fn nop(func_addr: u64, name: impl Into<String>) -> Self {
        let name_str = name.into();
        Self {
            func_addr,
            name: Some(name_str.clone()),
            output_relation: OutputRelation::constant(0, 64),
            side_effects: Vec::new(),
            preconditions: Vec::new(),
            arg_effects: Vec::new(),
            is_nop: true,
            never_returns: false,
            is_stub: false,
            fingerprint: SummaryFingerprint::from_addr_name(func_addr, &name_str),
        }
    }

    /// Apply this summary to a call site: substitute `args` into the output
    /// relation and return the resulting symbolic return value.
    ///
    /// Returns `Err` if any precondition is trivially violated.
    ///
    /// # Errors
    ///
    /// Returns [`SummaryError::PreconditionViolated`] when any registered
    /// precondition simplifies to `false`.
    pub fn apply(&self, args: &[SymExpr], _call_addr: u64) -> Result<SymExpr, SummaryError> {
        // Check preconditions.
        for pre in &self.preconditions {
            if pre.constraint.simplify() == SymExpr::ConstBool(false) {
                return Err(SummaryError::PreconditionViolated {
                    func: self.func_addr,
                    detail: pre.description.clone(),
                });
            }
        }
        Ok(self.output_relation.instantiate(args))
    }

    /// Return the function name or a hex address string.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("fn_{:#x}", self.func_addr))
    }

    /// Add a precondition.
    pub fn add_precondition(&mut self, pre: Precondition) {
        self.preconditions.push(pre);
    }

    /// Add a side effect.
    pub fn add_side_effect(&mut self, effect: SideEffect) {
        self.side_effects.push(effect);
    }

    /// Return `true` if any of the side effects terminate execution.
    #[must_use]
    pub fn may_terminate(&self) -> bool {
        self.never_returns
            || self
                .side_effects
                .iter()
                .any(|e| matches!(e, SideEffect::Terminates))
    }
}

// ─── SummaryFingerprint ───────────────────────────────────────────────────────

/// A cheap fingerprint used to look up summaries in the cache.
///
/// The fingerprint encodes the function address and an optional name hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SummaryFingerprint {
    /// Primary key: function address.
    pub addr: u64,
    /// FNV-1a hash of the function name (0 if no name).
    pub name_hash: u64,
    /// Number of arguments (0 if unknown).
    pub arg_count: usize,
}

impl SummaryFingerprint {
    #[must_use]
    pub const fn from_addr(addr: u64) -> Self {
        Self {
            addr,
            name_hash: 0,
            arg_count: 0,
        }
    }

    #[must_use]
    pub fn from_addr_name(addr: u64, name: &str) -> Self {
        Self {
            addr,
            name_hash: fnv1a(name),
            arg_count: 0,
        }
    }

    #[must_use]
    pub const fn with_arg_count(mut self, n: usize) -> Self {
        self.arg_count = n;
        self
    }
}

fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

// ─── SummaryCache ─────────────────────────────────────────────────────────────

/// Cache of function summaries, keyed by address and optionally by name.
///
/// Lookup priority:
/// 1. Exact address match.
/// 2. Name-hash match (for imported/external functions without known addresses).
#[derive(Debug, Default)]
pub struct SummaryCache {
    /// Primary lookup: `func_addr` → summary.
    by_addr: HashMap<u64, FunctionSummary>,
    /// Secondary lookup: `name_hash` → `func_addr` (for external functions at addr 0).
    by_name_hash: HashMap<u64, u64>,
    /// Lookup: function name → `func_addr`.
    by_name: HashMap<String, u64>,
    /// Hit counter.
    hits: u64,
    /// Miss counter.
    misses: u64,
}

impl SummaryCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a pre-populated cache with summaries for common libc / Win32
    /// functions.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut cache = Self::new();
        cache.insert_builtin_summaries();
        cache
    }

    /// Insert a summary into the cache.
    pub fn insert(&mut self, summary: FunctionSummary) {
        let addr = summary.func_addr;
        let name_hash = summary.fingerprint.name_hash;
        if let Some(name) = &summary.name {
            self.by_name.insert(name.clone(), addr);
        }
        if name_hash != 0 {
            self.by_name_hash.insert(name_hash, addr);
        }
        self.by_addr.insert(addr, summary);
    }

    /// Look up a summary by address.
    #[must_use]
    pub fn get_by_addr(&mut self, addr: u64) -> Option<&FunctionSummary> {
        if let Some(s) = self.by_addr.get(&addr) {
            self.hits += 1;
            Some(s)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Look up a summary by function name.
    #[must_use]
    pub fn get_by_name(&mut self, name: &str) -> Option<&FunctionSummary> {
        let addr = self.by_name.get(name).copied()?;
        if let Some(s) = self.by_addr.get(&addr) {
            self.hits += 1;
            Some(s)
        } else {
            let hash = fnv1a(name);
            let a2 = self.by_name_hash.get(&hash).copied()?;
            if let Some(s) = self.by_addr.get(&a2) {
                self.hits += 1;
                Some(s)
            } else {
                self.misses += 1;
                None
            }
        }
    }

    /// Look up by fingerprint (tries address first, then name hash).
    #[must_use]
    pub fn get_by_fingerprint(&mut self, fp: &SummaryFingerprint) -> Option<&FunctionSummary> {
        if let Some(s) = self.by_addr.get(&fp.addr) {
            self.hits += 1;
            return Some(s);
        }
        if fp.name_hash != 0
            && let Some(&addr) = self.by_name_hash.get(&fp.name_hash)
            && let Some(s) = self.by_addr.get(&addr)
        {
            self.hits += 1;
            return Some(s);
        }
        self.misses += 1;
        None
    }

    /// Apply the summary for `func_addr` to `args`.
    ///
    /// Returns `Err(SummaryError::NotFound)` if no summary is registered.
    ///
    /// # Errors
    ///
    /// Returns [`SummaryError::NotFound`] when no summary is registered for
    /// `func_addr`, or any error propagated from [`Summary::apply`].
    pub fn apply(
        &mut self,
        func_addr: u64,
        args: &[SymExpr],
        call_addr: u64,
    ) -> Result<SymExpr, SummaryError> {
        let summary = self
            .by_addr
            .get(&func_addr)
            .ok_or(SummaryError::NotFound(func_addr))?
            .clone();
        summary.apply(args, call_addr)
    }

    /// Apply a named summary.
    ///
    /// # Errors
    ///
    /// Returns [`SummaryError::NotFound`] when `name` is not registered, or
    /// any error propagated from [`Summary::apply`].
    pub fn apply_named(
        &mut self,
        name: &str,
        args: &[SymExpr],
        call_addr: u64,
    ) -> Result<SymExpr, SummaryError> {
        let summary = {
            let addr = self
                .by_name
                .get(name)
                .copied()
                .ok_or(SummaryError::NotFound(0))?;
            self.by_addr
                .get(&addr)
                .ok_or(SummaryError::NotFound(addr))?
                .clone()
        };
        summary.apply(args, call_addr)
    }

    /// Return cache statistics.
    #[must_use]
    pub const fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }

    /// Return the number of summaries in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_addr.len()
    }

    /// Return `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty()
    }

    /// Remove a summary by address.
    pub fn remove(&mut self, addr: u64) -> Option<FunctionSummary> {
        let s = self.by_addr.remove(&addr)?;
        if let Some(name) = &s.name {
            self.by_name.remove(name);
            self.by_name_hash.remove(&s.fingerprint.name_hash);
        }
        Some(s)
    }

    // ── Built-in summaries ────────────────────────────────────────────────────

    fn insert_builtin_summaries(&mut self) {
        // Common C runtime stubs at synthetic addresses (0xFFFF_0000_xxxx).
        const BASE: u64 = 0xFFFF_0000_0000;

        // strlen(s) → opaque length
        self.insert(FunctionSummary {
            func_addr: BASE | 0x01,
            name: Some("strlen".into()),
            output_relation: OutputRelation::new(
                SymExpr::var("strlen_result", SymType::BitVec(64)),
                64,
            ),
            side_effects: vec![SideEffect::MemoryRead {
                addr: SymExpr::var("arg0", SymType::Pointer),
            }],
            preconditions: Vec::new(),
            arg_effects: vec![ArgEffect::ReadOnly],
            is_nop: false,
            never_returns: false,
            is_stub: false,
            fingerprint: SummaryFingerprint::from_addr_name(BASE | 0x01, "strlen")
                .with_arg_count(1),
        });

        // malloc(size) → fresh pointer
        self.insert(FunctionSummary {
            func_addr: BASE | 0x02,
            name: Some("malloc".into()),
            output_relation: OutputRelation::new(SymExpr::var("malloc_ptr", SymType::Pointer), 64),
            side_effects: Vec::new(),
            preconditions: Vec::new(),
            arg_effects: vec![ArgEffect::ReadOnly],
            is_nop: false,
            never_returns: false,
            is_stub: false,
            fingerprint: SummaryFingerprint::from_addr_name(BASE | 0x02, "malloc")
                .with_arg_count(1),
        });

        // free(ptr) → void (returns 0)
        self.insert(FunctionSummary {
            func_addr: BASE | 0x03,
            name: Some("free".into()),
            output_relation: OutputRelation::constant(0, 64),
            side_effects: Vec::new(),
            preconditions: Vec::new(),
            arg_effects: vec![ArgEffect::Freed],
            is_nop: false,
            never_returns: false,
            is_stub: false,
            fingerprint: SummaryFingerprint::from_addr_name(BASE | 0x03, "free").with_arg_count(1),
        });

        // memcpy(dst, src, n) → dst
        self.insert(FunctionSummary {
            func_addr: BASE | 0x04,
            name: Some("memcpy".into()),
            output_relation: OutputRelation::identity(0, 64),
            side_effects: vec![
                SideEffect::MemoryRead {
                    addr: SymExpr::var("arg1", SymType::Pointer),
                },
                SideEffect::MemoryWrite {
                    addr: SymExpr::var("arg0", SymType::Pointer),
                    value: SymExpr::var("memcpy_data", SymType::BitVec(64)),
                },
            ],
            preconditions: Vec::new(),
            arg_effects: vec![ArgEffect::Written, ArgEffect::ReadOnly, ArgEffect::ReadOnly],
            is_nop: false,
            never_returns: false,
            is_stub: false,
            fingerprint: SummaryFingerprint::from_addr_name(BASE | 0x04, "memcpy")
                .with_arg_count(3),
        });

        // exit(code) → never returns
        self.insert(FunctionSummary {
            func_addr: BASE | 0x05,
            name: Some("exit".into()),
            output_relation: OutputRelation::constant(0, 64),
            side_effects: vec![SideEffect::Terminates],
            preconditions: Vec::new(),
            arg_effects: vec![ArgEffect::ReadOnly],
            is_nop: false,
            never_returns: true,
            is_stub: false,
            fingerprint: SummaryFingerprint::from_addr_name(BASE | 0x05, "exit").with_arg_count(1),
        });

        // memset(s, c, n) → s
        self.insert(FunctionSummary {
            func_addr: BASE | 0x06,
            name: Some("memset".into()),
            output_relation: OutputRelation::identity(0, 64),
            side_effects: vec![SideEffect::MemoryWrite {
                addr: SymExpr::var("arg0", SymType::Pointer),
                value: SymExpr::var("arg1", SymType::BitVec(8)),
            }],
            preconditions: Vec::new(),
            arg_effects: vec![ArgEffect::Written, ArgEffect::ReadOnly, ArgEffect::ReadOnly],
            is_nop: false,
            never_returns: false,
            is_stub: false,
            fingerprint: SummaryFingerprint::from_addr_name(BASE | 0x06, "memset")
                .with_arg_count(3),
        });
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Substitute all occurrences of variable `var_name` in `expr` with `replacement`.
fn substitute_expr(expr: &SymExpr, var_name: &str, replacement: &SymExpr) -> SymExpr {
    match expr {
        SymExpr::Var { name, .. } if name == var_name => replacement.clone(),
        SymExpr::ConstBv { .. } | SymExpr::ConstBool(_) | SymExpr::Var { .. } => expr.clone(),
        SymExpr::Add(l, r) => SymExpr::Add(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::Sub(l, r) => SymExpr::Sub(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::Mul(l, r) => SymExpr::Mul(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::And(l, r) => SymExpr::And(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::Or(l, r) => SymExpr::Or(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::Xor(l, r) => SymExpr::Xor(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::Not(e) => SymExpr::Not(Box::new(substitute_expr(e, var_name, replacement))),
        SymExpr::Neg(e) => SymExpr::Neg(Box::new(substitute_expr(e, var_name, replacement))),
        SymExpr::BoolNot(e) => {
            SymExpr::BoolNot(Box::new(substitute_expr(e, var_name, replacement)))
        }
        SymExpr::ZExt {
            expr: e,
            target_width,
        } => SymExpr::ZExt {
            expr: Box::new(substitute_expr(e, var_name, replacement)),
            target_width: *target_width,
        },
        SymExpr::SExt {
            expr: e,
            target_width,
        } => SymExpr::SExt {
            expr: Box::new(substitute_expr(e, var_name, replacement)),
            target_width: *target_width,
        },
        SymExpr::Extract { expr: e, hi, lo } => SymExpr::Extract {
            expr: Box::new(substitute_expr(e, var_name, replacement)),
            hi: *hi,
            lo: *lo,
        },
        SymExpr::Ite { cond, then_, else_ } => SymExpr::Ite {
            cond: Box::new(substitute_expr(cond, var_name, replacement)),
            then_: Box::new(substitute_expr(then_, var_name, replacement)),
            else_: Box::new(substitute_expr(else_, var_name, replacement)),
        },
        SymExpr::BoolAnd(l, r) => SymExpr::BoolAnd(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::BoolOr(l, r) => SymExpr::BoolOr(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::Eq(l, r) => SymExpr::Eq(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::Ne(l, r) => SymExpr::Ne(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::ULt(l, r) => SymExpr::ULt(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::ULe(l, r) => SymExpr::ULe(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::UGt(l, r) => SymExpr::UGt(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::UGe(l, r) => SymExpr::UGe(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::SLt(l, r) => SymExpr::SLt(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::SLe(l, r) => SymExpr::SLe(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::SGt(l, r) => SymExpr::SGt(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::SGe(l, r) => SymExpr::SGe(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::Shl(l, r) => SymExpr::Shl(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::LShr(l, r) => SymExpr::LShr(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::AShr(l, r) => SymExpr::AShr(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::Concat(l, r) => SymExpr::Concat(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::UDiv(l, r) => SymExpr::UDiv(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::SDiv(l, r) => SymExpr::SDiv(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::URem(l, r) => SymExpr::URem(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::SRem(l, r) => SymExpr::SRem(
            Box::new(substitute_expr(l, var_name, replacement)),
            Box::new(substitute_expr(r, var_name, replacement)),
        ),
        SymExpr::Load { addr, size } => SymExpr::Load {
            addr: Box::new(substitute_expr(addr, var_name, replacement)),
            size: *size,
        },
        SymExpr::Store { mem, addr, val } => SymExpr::Store {
            mem: Box::new(substitute_expr(mem, var_name, replacement)),
            addr: Box::new(substitute_expr(addr, var_name, replacement)),
            val: Box::new(substitute_expr(val, var_name, replacement)),
        },
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bv(v: u64, w: u32) -> SymExpr {
        SymExpr::bv(v, w)
    }

    #[test]
    fn test_output_relation_constant() {
        let rel = OutputRelation::constant(42, 64);
        let result = rel.instantiate(&[]);
        assert_eq!(result.as_const_u64(), Some(42));
    }

    #[test]
    fn test_output_relation_identity() {
        let rel = OutputRelation::identity(0, 64);
        let args = vec![bv(0xDEAD, 64)];
        let result = rel.instantiate(&args);
        assert_eq!(result.as_const_u64(), Some(0xDEAD));
    }

    #[test]
    fn test_function_summary_nop() {
        let s = FunctionSummary::nop(0x1000, "do_nothing");
        assert!(s.is_nop);
        assert!(!s.never_returns);
        assert_eq!(s.display_name(), "do_nothing");
    }

    #[test]
    fn test_function_summary_apply_constant() {
        let s = FunctionSummary::returns_zero(0x2000, "init");
        let result = s.apply(&[], 0x3000).unwrap();
        assert_eq!(result.as_const_u64(), Some(0));
    }

    #[test]
    fn test_function_summary_apply_identity() {
        let rel = OutputRelation::identity(0, 64);
        let mut s = FunctionSummary::opaque(0x4000, "passthrough");
        s.output_relation = rel;
        let args = vec![bv(99, 64)];
        let result = s.apply(&args, 0x5000).unwrap();
        assert_eq!(result.as_const_u64(), Some(99));
    }

    #[test]
    fn test_function_summary_precondition_violated() {
        let mut s = FunctionSummary::opaque(0x6000, "strict");
        s.add_precondition(Precondition::new(SymExpr::ConstBool(false), "always fails"));
        assert!(matches!(
            s.apply(&[], 0x7000),
            Err(SummaryError::PreconditionViolated { .. })
        ));
    }

    #[test]
    fn test_summary_cache_insert_and_lookup() {
        let mut cache = SummaryCache::new();
        let s = FunctionSummary::returns_zero(0xABCD, "test_fn");
        cache.insert(s);

        let found = cache.get_by_addr(0xABCD);
        assert!(found.is_some());
        assert_eq!(found.unwrap().func_addr, 0xABCD);
    }

    #[test]
    fn test_summary_cache_get_by_name() {
        let mut cache = SummaryCache::new();
        let s = FunctionSummary::nop(0x1111, "my_nop");
        cache.insert(s);

        let found = cache.get_by_name("my_nop");
        assert!(found.is_some());
    }

    #[test]
    fn test_summary_cache_miss() {
        let mut cache = SummaryCache::new();
        let found = cache.get_by_addr(0xDEAD);
        assert!(found.is_none());
        assert_eq!(cache.stats(), (0, 1));
    }

    #[test]
    fn test_summary_cache_apply() {
        let mut cache = SummaryCache::new();
        let rel = OutputRelation::constant(7, 64);
        let mut s = FunctionSummary::opaque(0x100, "lucky");
        s.output_relation = rel;
        cache.insert(s);

        let result = cache.apply(0x100, &[], 0x200).unwrap();
        assert_eq!(result.as_const_u64(), Some(7));
    }

    #[test]
    fn test_summary_cache_apply_not_found() {
        let mut cache = SummaryCache::new();
        let err = cache.apply(0xDEAD, &[], 0x0);
        assert!(matches!(err, Err(SummaryError::NotFound(0xDEAD))));
    }

    #[test]
    fn test_summary_cache_builtins() {
        let mut cache = SummaryCache::with_builtins();
        assert!(cache.get_by_name("strlen").is_some());
        assert!(cache.get_by_name("malloc").is_some());
        assert!(cache.get_by_name("free").is_some());
        assert!(cache.get_by_name("memcpy").is_some());
        assert!(cache.get_by_name("exit").is_some());
        assert!(cache.get_by_name("memset").is_some());
    }

    #[test]
    fn test_summary_cache_exit_never_returns() {
        let mut cache = SummaryCache::with_builtins();
        let exit_summary = cache.get_by_name("exit").unwrap();
        assert!(exit_summary.may_terminate());
        assert!(exit_summary.never_returns);
    }

    #[test]
    fn test_summary_cache_remove() {
        let mut cache = SummaryCache::new();
        cache.insert(FunctionSummary::nop(0x200, "removable"));
        assert_eq!(cache.len(), 1);
        let removed = cache.remove(0x200);
        assert!(removed.is_some());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_summary_fingerprint_hash() {
        let fp1 = SummaryFingerprint::from_addr_name(0x100, "strlen");
        let fp2 = SummaryFingerprint::from_addr_name(0x100, "strlen");
        let fp3 = SummaryFingerprint::from_addr_name(0x100, "printf");
        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_precondition_trivially_satisfied() {
        let p = Precondition::new(SymExpr::ConstBool(true), "trivial");
        assert!(p.is_trivially_satisfied());
        let p2 = Precondition::new(SymExpr::ConstBool(false), "never");
        assert!(!p2.is_trivially_satisfied());
    }

    #[test]
    fn test_substitute_expr_var() {
        let expr = SymExpr::var("arg0", SymType::BitVec(64));
        let replacement = bv(42, 64);
        let result = substitute_expr(&expr, "arg0", &replacement);
        assert_eq!(result.as_const_u64(), Some(42));
    }

    #[test]
    fn test_substitute_expr_add() {
        let expr = SymExpr::Add(
            Box::new(SymExpr::var("x", SymType::BitVec(64))),
            Box::new(bv(1, 64)),
        );
        let replacement = bv(10, 64);
        let result = substitute_expr(&expr, "x", &replacement);
        assert_eq!(result.simplify().as_const_u64(), Some(11));
    }
}
