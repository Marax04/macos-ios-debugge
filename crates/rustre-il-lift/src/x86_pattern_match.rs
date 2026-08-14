//! IR pattern-matching engine for x86 lifted code.
//!
//! Provides a composable pattern DSL for matching against `IrExpr` trees and
//! sequences of `Effect`s. Used by the deobfuscator, the optimizer, and the
//! calling-convention recovery pass.
//!
//! ## Pattern types
//!
//! | Pattern | Matches |
//! |---|---|
//! | `PAny` | any expression |
//! | `PConst(v)` | exactly `IrExpr::Const(v)` |
//! | `PAnyConst` | any `IrExpr::Const(_)` |
//! | `PReg(name)` | exactly `IrExpr::Reg(name)` |
//! | `PAnyReg` | any `IrExpr::Reg(_)` |
//! | `PAdd(a, b)` | `IrExpr::Add(a, b)` with sub-patterns |
//! | `PBind(name, sub)` | matches `sub` and binds the matched value to `name` |
//! | `PNot(p)` | matches when `p` does NOT match (negation) |
//!
//! A `Match` captures all `PBind` bindings from a successful pattern match.
//!
//! ## Usage
//!
//! ```
//! use rustre_il_lift::x86_pattern_match::ExprPat;
//! use rustre_il_lift::IrExpr;
//!
//! // Match any ADD of rsp with a constant — prologue stack adjustment.
//! let pat = ExprPat::Add(
//!     Box::new(ExprPat::Reg("rsp".into())),
//!     Box::new(ExprPat::Bind("offset".into(), Box::new(ExprPat::AnyConst))),
//! );
//!
//! let expr = IrExpr::Add(
//!     Box::new(IrExpr::Reg("rsp".into())),
//!     Box::new(IrExpr::Const(32)),
//! );
//!
//! let m = pat.match_expr(&expr).expect("pattern should match");
//! assert_eq!(m.get_const("offset"), Some(32));
//! ```
//!
//! The block was `rust,ignore` until 2026-07-29 and used `PAdd` / `PReg` /
//! `PBind` / `PAnyConst` — a `P`-prefixed naming that does not exist. The
//! real variants are `ExprPat::Add` / `Reg` / `Bind` / `AnyConst`.

use crate::{Effect, IrExpr};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Pattern AST
// ─────────────────────────────────────────────────────────────────────────────

/// An expression pattern.
#[derive(Debug, Clone)]
pub enum ExprPat {
    /// Matches any expression.
    Any,
    /// Matches `IrExpr::Const(v)` exactly.
    Const(u64),
    /// Matches `IrExpr::Const(_)` — any constant.
    AnyConst,
    /// Matches `IrExpr::Const(v)` where `v != 0`.
    NonZeroConst,
    /// Matches `IrExpr::Const(v)` where `v` is a power of two.
    PowerOfTwo,
    /// Matches `IrExpr::Reg(name)` exactly.
    Reg(String),
    /// Matches `IrExpr::Reg(_)` — any register.
    AnyReg,
    /// Matches `IrExpr::Undef`.
    Undef,
    /// Matches `IrExpr::Add(a, b)`.
    Add(Box<Self>, Box<Self>),
    /// Matches `IrExpr::Sub(a, b)`.
    Sub(Box<Self>, Box<Self>),
    /// Matches `IrExpr::Mul(a, b)`.
    Mul(Box<Self>, Box<Self>),
    /// Matches `IrExpr::And(a, b)`.
    And(Box<Self>, Box<Self>),
    /// Matches `IrExpr::Or(a, b)`.
    Or(Box<Self>, Box<Self>),
    /// Matches `IrExpr::Xor(a, b)`.
    Xor(Box<Self>, Box<Self>),
    /// Matches `IrExpr::Shl(a, b)`.
    Shl(Box<Self>, Box<Self>),
    /// Matches `IrExpr::Shr(a, b)`.
    Shr(Box<Self>, Box<Self>),
    /// Matches `IrExpr::Not(a)`.
    Not(Box<Self>),
    /// Matches `IrExpr::Deref(addr, size)`.
    Deref(Box<Self>, Option<u8>),
    /// Matches `IrExpr::CmpEqZero(e)`.
    CmpEqZero(Box<Self>),
    /// Matches `IrExpr::Parity(e)`.
    Parity(Box<Self>),
    /// Matches any commutative binary op (ADD or ADD with swapped operands).
    AddComm(Box<Self>, Box<Self>),
    /// Binds the matched expression to `name` in the capture map.
    Bind(String, Box<Self>),
    /// Matches iff the inner pattern does NOT match.
    Not_(Box<Self>),
    /// Matches iff both patterns match the same expression.
    And_(Box<Self>, Box<Self>),
    /// Matches iff at least one pattern matches.
    Or_(Box<Self>, Box<Self>),
}

impl ExprPat {
    /// Match `expr` against this pattern. Returns `Some(Match)` on success.
    #[must_use]
    pub fn match_expr(&self, expr: &IrExpr) -> Option<Match> {
        let mut m = Match::new();
        if self.match_into(expr, &mut m) {
            Some(m)
        } else {
            None
        }
    }

    fn match_into(&self, expr: &IrExpr, m: &mut Match) -> bool {
        match (self, expr) {
            (Self::Const(v), IrExpr::Const(c)) => v == c,
            (Self::NonZeroConst, IrExpr::Const(c)) => *c != 0,
            (Self::PowerOfTwo, IrExpr::Const(c)) => *c > 0 && c.is_power_of_two(),
            (Self::Reg(n), IrExpr::Reg(r)) => n == r,
            (Self::Any, _) | (Self::Undef, IrExpr::Undef) | (Self::AnyConst, IrExpr::Const(_)) | (Self::AnyReg, IrExpr::Reg(_)) => true,
            (Self::Add(pa, pb), IrExpr::Add(a, b)) | (Self::Sub(pa, pb), IrExpr::Sub(a, b)) | (Self::Mul(pa, pb), IrExpr::Mul(a, b)) | (Self::And(pa, pb), IrExpr::And(a, b)) | (Self::Or(pa, pb), IrExpr::Or(a, b)) | (Self::Xor(pa, pb), IrExpr::Xor(a, b)) | (Self::Shl(pa, pb), IrExpr::Shl(a, b)) | (Self::Shr(pa, pb), IrExpr::Shr(a, b)) => {
                let mut ma = m.clone();
                let mut mb = m.clone();
                if pa.match_into(a, &mut ma) && pb.match_into(b, &mut mb) {
                    m.merge(&ma);
                    m.merge(&mb);
                    true
                } else {
                    false
                }
            }
            (Self::AddComm(pa, pb), IrExpr::Add(a, b)) => {
                let mut ma = m.clone();
                let mut mb = m.clone();
                // Try both orderings.
                if pa.match_into(a, &mut ma) && pb.match_into(b, &mut mb) {
                    m.merge(&ma);
                    m.merge(&mb);
                    true
                } else {
                    let mut ma2 = m.clone();
                    let mut mb2 = m.clone();
                    if pa.match_into(b, &mut ma2) && pb.match_into(a, &mut mb2) {
                        m.merge(&ma2);
                        m.merge(&mb2);
                        true
                    } else {
                        false
                    }
                }
            }
            (Self::Not(pa), IrExpr::Not(a)) => pa.match_into(a, m),
            (Self::Deref(paddr, sz), IrExpr::Deref(addr, actual_sz)) => {
                if let Some(s) = sz
                    && s != actual_sz {
                        return false;
                    }
                paddr.match_into(addr, m)
            }
            (Self::CmpEqZero(p), IrExpr::CmpEqZero(e)) | (Self::Parity(p), IrExpr::Parity(e)) => p.match_into(e, m),
            (Self::Bind(name, p), _) => {
                if p.match_into(expr, m) {
                    m.bindings.insert(name.clone(), expr.clone());
                    true
                } else {
                    false
                }
            }
            (Self::Not_(p), _) => !p.match_into(expr, &mut m.clone()),
            (Self::And_(p1, p2), _) => {
                let mut m1 = m.clone();
                p1.match_into(expr, &mut m1) && p2.match_into(expr, m)
            }
            (Self::Or_(p1, p2), _) => {
                let mut m1 = m.clone();
                if p1.match_into(expr, &mut m1) {
                    m.merge(&m1);
                    true
                } else {
                    p2.match_into(expr, m)
                }
            }
            _ => false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Match (capture map)
// ─────────────────────────────────────────────────────────────────────────────

/// The bindings captured by a successful pattern match.
#[derive(Debug, Clone, Default)]
pub struct Match {
    /// Named bindings from `ExprPat::Bind`.
    pub bindings: HashMap<String, IrExpr>,
}

impl Match {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a binding by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&IrExpr> {
        self.bindings.get(name)
    }

    /// Look up a binding and extract its constant value.
    #[must_use]
    pub fn get_const(&self, name: &str) -> Option<u64> {
        match self.bindings.get(name)? {
            IrExpr::Const(v) => Some(*v),
            _ => None,
        }
    }

    /// Look up a binding and extract its register name.
    #[must_use]
    pub fn get_reg(&self, name: &str) -> Option<&str> {
        match self.bindings.get(name)? {
            IrExpr::Reg(r) => Some(r.as_str()),
            _ => None,
        }
    }

    /// `true` if the binding map is empty (no `PBind` patterns were used).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    fn merge(&mut self, other: &Self) {
        for (k, v) in &other.bindings {
            self.bindings.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Effect patterns
// ─────────────────────────────────────────────────────────────────────────────

/// A pattern for a single `Effect`.
#[derive(Debug, Clone)]
pub enum EffectPat {
    /// Match any effect.
    AnyEffect,
    /// Match `Effect::RegWrite { reg, value }` where `reg_pat` and `val_pat` match.
    RegWrite { reg: ExprPat, value: ExprPat },
    /// Match `Effect::MemWrite { addr, value, size }`.
    MemWrite {
        addr: ExprPat,
        value: ExprPat,
        size: Option<u8>,
    },
    /// Match `Effect::MemRead { addr, dest, size }`.
    MemRead {
        addr: ExprPat,
        dest: ExprPat,
        size: Option<u8>,
    },
    /// Match `Effect::Branch { target, condition }`.
    Branch {
        target: ExprPat,
        conditional: Option<bool>,
    },
    /// Match `Effect::Call { target }`.
    Call { target: ExprPat },
    /// Match `Effect::Return`.
    Return,
    /// Match `Effect::Syscall`.
    Syscall,
    /// Match `Effect::Intrinsic { name, .. }` where `name_substr` is a substring of the name.
    Intrinsic { name_substr: String },
    /// Bind the matched effect to `name` in the capture map.
    BindEffect(String, Box<Self>),
}

impl EffectPat {
    /// Match `eff` against this pattern. Returns `Some(Match)` on success.
    #[must_use]
    pub fn match_effect(&self, eff: &Effect) -> Option<Match> {
        let mut m = Match::new();
        if self.match_into(eff, &mut m) {
            Some(m)
        } else {
            None
        }
    }

    fn match_into(&self, eff: &Effect, m: &mut Match) -> bool {
        match (self, eff) {
            (Self::RegWrite { reg, value }, Effect::RegWrite { reg: r, value: v }) => {
                let reg_expr = IrExpr::Reg(r.clone());
                let mut mr = m.clone();
                let mut mv = m.clone();
                if reg.match_into(&reg_expr, &mut mr) && value.match_into(v, &mut mv) {
                    m.merge(&mr);
                    m.merge(&mv);
                    true
                } else {
                    false
                }
            }
            (
                Self::MemWrite { addr, value, size },
                Effect::MemWrite {
                    addr: a,
                    value: v,
                    size: s,
                },
            ) => {
                if let Some(sz) = size
                    && sz != s {
                        return false;
                    }
                let mut ma = m.clone();
                let mut mv = m.clone();
                if addr.match_into(a, &mut ma) && value.match_into(v, &mut mv) {
                    m.merge(&ma);
                    m.merge(&mv);
                    true
                } else {
                    false
                }
            }
            (
                Self::MemRead { addr, dest, size },
                Effect::MemRead {
                    addr: a,
                    dest: d,
                    size: s,
                },
            ) => {
                if let Some(sz) = size
                    && sz != s {
                        return false;
                    }
                let dest_expr = IrExpr::Reg(d.clone());
                let mut ma = m.clone();
                let mut md = m.clone();
                if addr.match_into(a, &mut ma) && dest.match_into(&dest_expr, &mut md) {
                    m.merge(&ma);
                    m.merge(&md);
                    true
                } else {
                    false
                }
            }
            (
                Self::Branch {
                    target,
                    conditional,
                },
                Effect::Branch {
                    target: t,
                    condition: c,
                },
            ) => {
                if let Some(cond_req) = conditional
                    && *cond_req != c.is_some() {
                        return false;
                    }
                target.match_into(t, m)
            }
            (Self::Call { target }, Effect::Call { target: t }) => target.match_into(t, m),
            (Self::AnyEffect, _) | (Self::Return, Effect::Return { .. }) | (Self::Syscall, Effect::Syscall { .. }) => true,
            (Self::Intrinsic { name_substr }, Effect::Intrinsic { name, .. }) => {
                name.contains(name_substr.as_str())
            }
            (Self::BindEffect(name, p), _)
                if p.match_into(eff, m) => {
                    // Store a dummy marker for the bound effect.
                    m.bindings.insert(name.clone(), IrExpr::Const(0x00ef_fec7));
                    true
                }
            _ => false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sequence patterns
// ─────────────────────────────────────────────────────────────────────────────

/// Match a contiguous sequence of effects against a list of `EffectPat`s.
/// Returns the combined `Match` if every pattern matches in order.
#[must_use]
pub fn match_sequence(effects: &[Effect], patterns: &[EffectPat]) -> Option<Match> {
    if patterns.len() > effects.len() {
        return None;
    }
    let mut combined = Match::new();
    for (eff, pat) in effects.iter().zip(patterns.iter()) {
        let m = pat.match_effect(eff)?;
        combined.merge(&m);
    }
    Some(combined)
}

/// Scan `effects` for the first occurrence of a contiguous match against
/// `patterns`. Returns the start index and the combined `Match`.
#[must_use]
pub fn scan_sequence(effects: &[Effect], patterns: &[EffectPat]) -> Option<(usize, Match)> {
    if patterns.is_empty() {
        return Some((0, Match::new()));
    }
    for start in 0..effects
        .len()
        .saturating_sub(patterns.len())
        .saturating_add(1)
    {
        if start + patterns.len() > effects.len() {
            break;
        }
        if let Some(m) = match_sequence(&effects[start..start + patterns.len()], patterns) {
            return Some((start, m));
        }
    }
    None
}

/// Find all non-overlapping occurrences of `patterns` in `effects`.
#[must_use]
pub fn find_all(effects: &[Effect], patterns: &[EffectPat]) -> Vec<(usize, Match)> {
    let mut results = Vec::new();
    let mut offset = 0;
    while offset < effects.len() {
        match scan_sequence(&effects[offset..], patterns) {
            Some((rel, m)) => {
                let abs = offset + rel;
                results.push((abs, m));
                offset = abs + patterns.len().max(1);
            }
            None => break,
        }
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Predefined patterns
// ─────────────────────────────────────────────────────────────────────────────

/// Match `rsp := rsp - N` (SP decrement, as in PUSH or function prologue).
#[must_use]
pub fn pat_sp_decrement() -> EffectPat {
    EffectPat::RegWrite {
        reg: ExprPat::Or_(
            Box::new(ExprPat::Reg("rsp".into())),
            Box::new(ExprPat::Reg("esp".into())),
        ),
        value: ExprPat::Sub(
            Box::new(ExprPat::Or_(
                Box::new(ExprPat::Reg("rsp".into())),
                Box::new(ExprPat::Reg("esp".into())),
            )),
            Box::new(ExprPat::Bind(
                "stack_adjust".into(),
                Box::new(ExprPat::AnyConst),
            )),
        ),
    }
}

/// Match `rsp := rsp + N` (SP increment, as in POP or RET).
#[must_use]
pub fn pat_sp_increment() -> EffectPat {
    EffectPat::RegWrite {
        reg: ExprPat::Or_(
            Box::new(ExprPat::Reg("rsp".into())),
            Box::new(ExprPat::Reg("esp".into())),
        ),
        value: ExprPat::Add(
            Box::new(ExprPat::Or_(
                Box::new(ExprPat::Reg("rsp".into())),
                Box::new(ExprPat::Reg("esp".into())),
            )),
            Box::new(ExprPat::Bind(
                "stack_adjust".into(),
                Box::new(ExprPat::AnyConst),
            )),
        ),
    }
}

/// Match any flag write (register name in CF/PF/AF/ZF/SF/OF).
#[must_use]
pub fn pat_any_flag_write(flag: &str) -> EffectPat {
    EffectPat::RegWrite {
        reg: ExprPat::Reg(flag.into()),
        value: ExprPat::Any,
    }
}

/// Match a zero-write to a flag (flag := 0).
#[must_use]
pub fn pat_flag_clear(flag: &str) -> EffectPat {
    EffectPat::RegWrite {
        reg: ExprPat::Reg(flag.into()),
        value: ExprPat::Const(0),
    }
}

/// Match a write of ZF from a `CmpEqZero` expression (the canonical ZF pattern).
#[must_use]
pub fn pat_zf_from_cmp() -> EffectPat {
    EffectPat::RegWrite {
        reg: ExprPat::Reg("zf".into()),
        value: ExprPat::CmpEqZero(Box::new(ExprPat::Bind(
            "cmp_operand".into(),
            Box::new(ExprPat::Any),
        ))),
    }
}

/// Match a direct memory store at a constant address.
#[must_use]
pub fn pat_mem_store_const_addr() -> EffectPat {
    EffectPat::MemWrite {
        addr: ExprPat::Bind("addr".into(), Box::new(ExprPat::AnyConst)),
        value: ExprPat::Bind("value".into(), Box::new(ExprPat::Any)),
        size: None,
    }
}

/// Match an unconditional branch to a constant target.
#[must_use]
pub fn pat_direct_jmp() -> EffectPat {
    EffectPat::Branch {
        target: ExprPat::Bind("target".into(), Box::new(ExprPat::AnyConst)),
        conditional: Some(false),
    }
}

/// Match a conditional branch (any condition).
#[must_use]
pub fn pat_cond_branch() -> EffectPat {
    EffectPat::Branch {
        target: ExprPat::Bind("target".into(), Box::new(ExprPat::Any)),
        conditional: Some(true),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern library: common idioms
// ─────────────────────────────────────────────────────────────────────────────

/// Recognise the `XOR reg, reg` zeroing pattern in an effect slice.
/// Returns the register name if matched.
#[must_use]
pub fn detect_xor_zeroing(effects: &[Effect]) -> Option<String> {
    for eff in effects {
        if let Effect::RegWrite {
            reg,
            value: IrExpr::Const(0),
        } = eff
            && !reg.starts_with("__")
                && !["cf", "pf", "af", "zf", "sf", "of"].contains(&reg.as_str())
            {
                return Some(reg.clone());
            }
    }
    None
}

/// Recognise a tail call: a direct branch preceded by RSP restoration.
#[must_use]
pub fn detect_tail_call(effects: &[Effect]) -> Option<u64> {
    let has_sp_restore = effects.iter().any(|e| {
        matches!(e, Effect::RegWrite { reg, value: IrExpr::Reg(v) }
                 if (reg == "rsp" || reg == "esp") && (v == "rbp" || v == "ebp"))
    });
    if !has_sp_restore {
        return None;
    }
    effects.iter().find_map(|e| {
        if let Effect::Branch {
            target: IrExpr::Const(t),
            condition: None,
        } = e
        {
            Some(*t)
        } else {
            None
        }
    })
}

/// Recognise a loop header: an effect slice ending with a conditional back-edge.
#[must_use]
pub fn detect_loop_back_edge(effects: &[Effect], loop_header_addr: u64) -> bool {
    effects.iter().any(|e| {
        matches!(e, Effect::Branch { target: IrExpr::Const(t), condition: Some(_) }
                 if *t == loop_header_addr)
    })
}

/// Count PUSH operations in the effect list (SP decrements + mem writes).
#[must_use]
pub fn count_pushes(effects: &[Effect]) -> usize {
    effects
        .iter()
        .filter(|e| {
            matches!(e, Effect::MemWrite { addr: IrExpr::Reg(sp), .. }
                 if sp == "rsp" || sp == "esp")
        })
        .count()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Effect, IrExpr};

    fn reg(r: &str) -> IrExpr {
        IrExpr::Reg(r.into())
    }
    fn cst(v: u64) -> IrExpr {
        IrExpr::Const(v)
    }
    fn add(a: IrExpr, b: IrExpr) -> IrExpr {
        IrExpr::Add(Box::new(a), Box::new(b))
    }
    fn sub(a: IrExpr, b: IrExpr) -> IrExpr {
        IrExpr::Sub(Box::new(a), Box::new(b))
    }

    // ── ExprPat ──────────────────────────────────────────────────────────────

    #[test]
    fn any_matches_everything() {
        assert!(ExprPat::Any.match_expr(&cst(42)).is_some());
        assert!(ExprPat::Any.match_expr(&reg("rax")).is_some());
        assert!(ExprPat::Any.match_expr(&IrExpr::Undef).is_some());
    }

    #[test]
    fn const_matches_exact() {
        assert!(ExprPat::Const(42).match_expr(&cst(42)).is_some());
        assert!(ExprPat::Const(42).match_expr(&cst(43)).is_none());
    }

    #[test]
    fn any_const_matches_any_const() {
        assert!(ExprPat::AnyConst.match_expr(&cst(0)).is_some());
        assert!(ExprPat::AnyConst.match_expr(&cst(u64::MAX)).is_some());
        assert!(ExprPat::AnyConst.match_expr(&reg("rax")).is_none());
    }

    #[test]
    fn nonzero_const() {
        assert!(ExprPat::NonZeroConst.match_expr(&cst(1)).is_some());
        assert!(ExprPat::NonZeroConst.match_expr(&cst(0)).is_none());
    }

    #[test]
    fn power_of_two() {
        assert!(ExprPat::PowerOfTwo.match_expr(&cst(8)).is_some());
        assert!(ExprPat::PowerOfTwo.match_expr(&cst(7)).is_none());
        assert!(ExprPat::PowerOfTwo.match_expr(&cst(0)).is_none());
    }

    #[test]
    fn reg_exact() {
        assert!(ExprPat::Reg("rax".into()).match_expr(&reg("rax")).is_some());
        assert!(ExprPat::Reg("rax".into()).match_expr(&reg("rbx")).is_none());
    }

    #[test]
    fn any_reg() {
        assert!(ExprPat::AnyReg.match_expr(&reg("r15")).is_some());
        assert!(ExprPat::AnyReg.match_expr(&cst(0)).is_none());
    }

    #[test]
    fn undef_matches_undef() {
        assert!(ExprPat::Undef.match_expr(&IrExpr::Undef).is_some());
        assert!(ExprPat::Undef.match_expr(&cst(0)).is_none());
    }

    #[test]
    fn add_pattern() {
        let e = add(reg("rax"), cst(1));
        let p = ExprPat::Add(Box::new(ExprPat::AnyReg), Box::new(ExprPat::AnyConst));
        assert!(p.match_expr(&e).is_some());
    }

    #[test]
    fn add_pattern_wrong_order() {
        let e = add(cst(1), reg("rax")); // const first, reg second
        let p = ExprPat::Add(Box::new(ExprPat::AnyReg), Box::new(ExprPat::AnyConst));
        assert!(p.match_expr(&e).is_none()); // non-commutative
    }

    #[test]
    fn add_comm_matches_either_order() {
        let e1 = add(reg("rax"), cst(1));
        let e2 = add(cst(1), reg("rax"));
        let p = ExprPat::AddComm(Box::new(ExprPat::AnyReg), Box::new(ExprPat::AnyConst));
        assert!(p.match_expr(&e1).is_some());
        assert!(p.match_expr(&e2).is_some());
    }

    #[test]
    fn sub_pattern() {
        let e = sub(reg("rsp"), cst(8));
        let p = ExprPat::Sub(
            Box::new(ExprPat::Reg("rsp".into())),
            Box::new(ExprPat::Const(8)),
        );
        assert!(p.match_expr(&e).is_some());
    }

    #[test]
    fn not_pattern() {
        let e = IrExpr::Not(Box::new(reg("rax")));
        let p = ExprPat::Not(Box::new(ExprPat::Reg("rax".into())));
        assert!(p.match_expr(&e).is_some());
    }

    #[test]
    fn cmp_eq_zero_pattern() {
        let e = IrExpr::CmpEqZero(Box::new(reg("rax")));
        let p = ExprPat::CmpEqZero(Box::new(ExprPat::AnyReg));
        assert!(p.match_expr(&e).is_some());
    }

    #[test]
    fn parity_pattern() {
        let e = IrExpr::Parity(Box::new(reg("rbx")));
        let p = ExprPat::Parity(Box::new(ExprPat::AnyReg));
        assert!(p.match_expr(&e).is_some());
    }

    #[test]
    fn deref_any_size() {
        let e = IrExpr::Deref(Box::new(reg("rax")), 8);
        let p = ExprPat::Deref(Box::new(ExprPat::AnyReg), None);
        assert!(p.match_expr(&e).is_some());
    }

    #[test]
    fn deref_specific_size_match() {
        let e = IrExpr::Deref(Box::new(reg("rax")), 8);
        let p = ExprPat::Deref(Box::new(ExprPat::AnyReg), Some(8));
        assert!(p.match_expr(&e).is_some());
    }

    #[test]
    fn deref_specific_size_no_match() {
        let e = IrExpr::Deref(Box::new(reg("rax")), 4);
        let p = ExprPat::Deref(Box::new(ExprPat::AnyReg), Some(8));
        assert!(p.match_expr(&e).is_none());
    }

    // ── Bind ────────────────────────────────────────────────────────────────

    #[test]
    fn bind_captures_value() {
        let e = cst(100);
        let p = ExprPat::Bind("x".into(), Box::new(ExprPat::AnyConst));
        let m = p.match_expr(&e).unwrap();
        assert_eq!(m.get_const("x"), Some(100));
    }

    #[test]
    fn bind_in_nested_pattern() {
        let e = add(reg("rsp"), cst(8));
        let p = ExprPat::Add(
            Box::new(ExprPat::Reg("rsp".into())),
            Box::new(ExprPat::Bind("offset".into(), Box::new(ExprPat::AnyConst))),
        );
        let m = p.match_expr(&e).unwrap();
        assert_eq!(m.get_const("offset"), Some(8));
    }

    #[test]
    fn bind_fails_when_sub_pattern_fails() {
        let e = reg("rax");
        let p = ExprPat::Bind("x".into(), Box::new(ExprPat::AnyConst));
        assert!(p.match_expr(&e).is_none());
    }

    // ── Negation and combinators ─────────────────────────────────────────────

    #[test]
    fn not_combinator_negates() {
        let p = ExprPat::Not_(Box::new(ExprPat::AnyConst));
        assert!(p.match_expr(&reg("rax")).is_some()); // reg is not a const → ok
        assert!(p.match_expr(&cst(5)).is_none()); // const → not ok
    }

    #[test]
    fn or_combinator_either() {
        let p = ExprPat::Or_(
            Box::new(ExprPat::Reg("rax".into())),
            Box::new(ExprPat::Reg("rbx".into())),
        );
        assert!(p.match_expr(&reg("rax")).is_some());
        assert!(p.match_expr(&reg("rbx")).is_some());
        assert!(p.match_expr(&reg("rcx")).is_none());
    }

    #[test]
    fn and_combinator_both() {
        let p = ExprPat::And_(
            Box::new(ExprPat::AnyReg),
            Box::new(ExprPat::Not_(Box::new(ExprPat::Reg("rsp".into())))),
        );
        assert!(p.match_expr(&reg("rax")).is_some()); // any reg except rsp
        assert!(p.match_expr(&reg("rsp")).is_none());
    }

    // ── EffectPat ────────────────────────────────────────────────────────────

    #[test]
    fn effect_any_matches_all() {
        let e = Effect::RegWrite {
            reg: "rax".into(),
            value: cst(0),
        };
        assert!(EffectPat::AnyEffect.match_effect(&e).is_some());
    }

    #[test]
    fn effect_reg_write_match() {
        let e = Effect::RegWrite {
            reg: "rax".into(),
            value: cst(42),
        };
        let p = EffectPat::RegWrite {
            reg: ExprPat::Reg("rax".into()),
            value: ExprPat::Const(42),
        };
        assert!(p.match_effect(&e).is_some());
    }

    #[test]
    fn effect_reg_write_no_match() {
        let e = Effect::RegWrite {
            reg: "rbx".into(),
            value: cst(42),
        };
        let p = EffectPat::RegWrite {
            reg: ExprPat::Reg("rax".into()),
            value: ExprPat::AnyConst,
        };
        assert!(p.match_effect(&e).is_none());
    }

    #[test]
    fn effect_mem_write_match() {
        let e = Effect::MemWrite {
            addr: cst(0x1000),
            value: cst(0),
            size: 8,
        };
        let p = EffectPat::MemWrite {
            addr: ExprPat::AnyConst,
            value: ExprPat::Any,
            size: Some(8),
        };
        assert!(p.match_effect(&e).is_some());
    }

    #[test]
    fn effect_mem_write_size_mismatch() {
        let e = Effect::MemWrite {
            addr: cst(0x1000),
            value: cst(0),
            size: 4,
        };
        let p = EffectPat::MemWrite {
            addr: ExprPat::Any,
            value: ExprPat::Any,
            size: Some(8),
        };
        assert!(p.match_effect(&e).is_none());
    }

    #[test]
    fn effect_branch_unconditional() {
        let e = Effect::Branch {
            target: cst(0x0040_1000),
            condition: None,
        };
        let p = EffectPat::Branch {
            target: ExprPat::AnyConst,
            conditional: Some(false),
        };
        assert!(p.match_effect(&e).is_some());
    }

    #[test]
    fn effect_branch_conditional_mismatch() {
        let e = Effect::Branch {
            target: cst(0x0040_1000),
            condition: None,
        };
        let p = EffectPat::Branch {
            target: ExprPat::AnyConst,
            conditional: Some(true),
        };
        assert!(p.match_effect(&e).is_none());
    }

    #[test]
    fn effect_return_matches() {
        let e = Effect::Return { value: None };
        assert!(EffectPat::Return.match_effect(&e).is_some());
    }

    #[test]
    fn effect_syscall_matches() {
        let e = Effect::Syscall { nr: cst(60) };
        assert!(EffectPat::Syscall.match_effect(&e).is_some());
    }

    #[test]
    fn effect_intrinsic_substr() {
        let e = Effect::Intrinsic {
            name: "x86.cpuid".into(),
            args: vec![],
        };
        let p = EffectPat::Intrinsic {
            name_substr: "cpuid".into(),
        };
        assert!(p.match_effect(&e).is_some());
        let pno = EffectPat::Intrinsic {
            name_substr: "rdtsc".into(),
        };
        assert!(pno.match_effect(&e).is_none());
    }

    // ── Sequence matching ────────────────────────────────────────────────────

    #[test]
    fn sequence_full_match() {
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: cst(1),
            },
            Effect::RegWrite {
                reg: "rbx".into(),
                value: cst(2),
            },
        ];
        let patterns = vec![
            EffectPat::RegWrite {
                reg: ExprPat::AnyReg,
                value: ExprPat::AnyConst,
            },
            EffectPat::RegWrite {
                reg: ExprPat::AnyReg,
                value: ExprPat::AnyConst,
            },
        ];
        assert!(match_sequence(&effects, &patterns).is_some());
    }

    #[test]
    fn sequence_partial_match() {
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: cst(1),
            },
            Effect::Return { value: None },
        ];
        let patterns = vec![
            EffectPat::RegWrite {
                reg: ExprPat::AnyReg,
                value: ExprPat::AnyConst,
            },
            EffectPat::Return,
        ];
        assert!(match_sequence(&effects, &patterns).is_some());
    }

    #[test]
    fn sequence_no_match() {
        let effects = vec![Effect::RegWrite {
            reg: "rax".into(),
            value: cst(1),
        }];
        let patterns = vec![EffectPat::Return];
        assert!(match_sequence(&effects, &patterns).is_none());
    }

    #[test]
    fn scan_sequence_finds_needle() {
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: cst(0),
            },
            Effect::RegWrite {
                reg: "rbx".into(),
                value: cst(0),
            },
            Effect::Return { value: None },
        ];
        let patterns = vec![EffectPat::Return];
        let result = scan_sequence(&effects, &patterns);
        assert_eq!(result.map(|(i, _)| i), Some(2));
    }

    #[test]
    fn find_all_multiple_occurrences() {
        let effects = vec![
            Effect::Return { value: None },
            Effect::RegWrite {
                reg: "rax".into(),
                value: cst(0),
            },
            Effect::Return { value: None },
        ];
        let patterns = vec![EffectPat::Return];
        let all = find_all(&effects, &patterns);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, 0);
        assert_eq!(all[1].0, 2);
    }

    // ── Predefined patterns ──────────────────────────────────────────────────

    #[test]
    fn sp_decrement_matches_push_style() {
        let eff = Effect::RegWrite {
            reg: "rsp".into(),
            value: sub(reg("rsp"), cst(8)),
        };
        let m = pat_sp_decrement().match_effect(&eff);
        assert!(m.is_some());
        assert_eq!(m.unwrap().get_const("stack_adjust"), Some(8));
    }

    #[test]
    fn sp_increment_matches_pop_style() {
        let eff = Effect::RegWrite {
            reg: "rsp".into(),
            value: add(reg("rsp"), cst(8)),
        };
        let m = pat_sp_increment().match_effect(&eff);
        assert!(m.is_some());
        assert_eq!(m.unwrap().get_const("stack_adjust"), Some(8));
    }

    #[test]
    fn flag_clear_matches_const_zero() {
        let eff = Effect::RegWrite {
            reg: "cf".into(),
            value: cst(0),
        };
        assert!(pat_flag_clear("cf").match_effect(&eff).is_some());
    }

    #[test]
    fn flag_clear_no_match_nonzero() {
        let eff = Effect::RegWrite {
            reg: "cf".into(),
            value: cst(1),
        };
        assert!(pat_flag_clear("cf").match_effect(&eff).is_none());
    }

    #[test]
    fn zf_from_cmp_matches() {
        let eff = Effect::RegWrite {
            reg: "zf".into(),
            value: IrExpr::CmpEqZero(Box::new(reg("rax"))),
        };
        let m = pat_zf_from_cmp().match_effect(&eff);
        assert!(m.is_some());
        assert_eq!(m.unwrap().get_reg("cmp_operand"), Some("rax"));
    }

    #[test]
    fn direct_jmp_matches() {
        let eff = Effect::Branch {
            target: cst(0x0040_1000),
            condition: None,
        };
        let m = pat_direct_jmp().match_effect(&eff);
        assert!(m.is_some());
        assert_eq!(m.unwrap().get_const("target"), Some(0x0040_1000));
    }

    // ── High-level detectors ─────────────────────────────────────────────────

    #[test]
    fn detect_xor_zeroing_finds_rax() {
        let effects = vec![Effect::RegWrite {
            reg: "rax".into(),
            value: cst(0),
        }];
        assert_eq!(detect_xor_zeroing(&effects), Some("rax".into()));
    }

    #[test]
    fn detect_xor_zeroing_ignores_flags() {
        let effects = vec![Effect::RegWrite {
            reg: "zf".into(),
            value: cst(0),
        }];
        assert_eq!(detect_xor_zeroing(&effects), None);
    }

    #[test]
    fn count_pushes_in_prologue() {
        let effects = vec![
            Effect::RegWrite {
                reg: "rsp".into(),
                value: sub(reg("rsp"), cst(8)),
            },
            Effect::MemWrite {
                addr: reg("rsp"),
                value: reg("rbp"),
                size: 8,
            },
        ];
        assert_eq!(count_pushes(&effects), 1);
    }

    #[test]
    fn detect_loop_back_edge() {
        let effects = vec![Effect::Branch {
            target: cst(0x1000),
            condition: Some(IrExpr::Reg("zf".into())),
        }];
        assert!(super::detect_loop_back_edge(&effects, 0x1000));
        assert!(!super::detect_loop_back_edge(&effects, 0x2000));
    }
}
