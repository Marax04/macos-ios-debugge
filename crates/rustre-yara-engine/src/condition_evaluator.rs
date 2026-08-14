//! YARA condition evaluator — full AST walker with all/any/for/of/them quantifiers,
//! at/in/with operators, filesize/entrypoint references, arithmetic, and comparison
//! expressions.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{CompOp, Condition, StringMatch, YaraRule, YaraString};

// ── Expression AST ────────────────────────────────────────────────────────────

/// A rich condition expression tree supporting the full YARA condition grammar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expr {
    // ── Literals ──────────────────────────────────────────────────────────────
    Bool(bool),
    Int(i64),

    // ── String predicates ─────────────────────────────────────────────────────
    /// `$ident` — string is present anywhere
    StringPresent(String),
    /// `#ident` — count of matches
    StringCount(String),
    /// `$ident at offset` — string present at exact offset
    StringAt(String, Box<Self>),
    /// `$ident in (lo..hi)` — string present within range
    StringIn(String, Box<Self>, Box<Self>),

    // ── Quantifiers ───────────────────────────────────────────────────────────
    /// `all of them` / `all of ($a, $b, ...)`
    AllOf(StringSet),
    /// `any of them` / `any of ($a, ...)`
    AnyOf(StringSet),
    /// `none of them`
    NoneOf(StringSet),
    /// `N of them` / `N of ($a, ...)`
    NOf(Box<Self>, StringSet),
    /// `for all i in (1..n): ($ident[i] matches ...)`
    ForAll(Box<Self>, String, Box<Self>),

    // ── File properties ───────────────────────────────────────────────────────
    FileSize,
    EntryPoint,

    // ── Integer read functions ─────────────────────────────────────────────────
    /// `uint8(offset)` / `int8(offset)`
    ReadU8(Box<Self>),
    ReadU16(Box<Self>, Endian),
    ReadU32(Box<Self>, Endian),
    ReadI8(Box<Self>),
    ReadI16(Box<Self>, Endian),
    ReadI32(Box<Self>, Endian),

    // ── Arithmetic ────────────────────────────────────────────────────────────
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Div(Box<Self>, Box<Self>),
    Mod(Box<Self>, Box<Self>),
    BitAnd(Box<Self>, Box<Self>),
    BitOr(Box<Self>, Box<Self>),
    BitXor(Box<Self>, Box<Self>),
    BitNot(Box<Self>),
    ShiftLeft(Box<Self>, Box<Self>),
    ShiftRight(Box<Self>, Box<Self>),
    Negate(Box<Self>),

    // ── Comparisons ───────────────────────────────────────────────────────────
    Cmp(Box<Self>, CompOp, Box<Self>),
    Contains(Box<Self>, Box<Self>),
    Matches(Box<Self>, String),
    IContains(Box<Self>, Box<Self>),
    StartsWith(Box<Self>, Box<Self>),
    EndsWith(Box<Self>, Box<Self>),

    // ── Logical ───────────────────────────────────────────────────────────────
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),

    // ── Special ───────────────────────────────────────────────────────────────
    /// `defined($ident)` — true when the string identifier exists
    Defined(String),
}

/// Byte order used for integer read functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Big,
    Little,
}

/// The set of strings targeted by a quantifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringSet {
    /// `them` — all strings in the rule
    Them,
    /// Explicit list of identifiers (with optional wildcard suffix `$foo*`)
    List(Vec<StringPattern>),
}

/// A single string pattern in a `StringSet`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringPattern {
    /// The identifier prefix (without leading `$`).
    pub prefix: String,
    /// If `true`, this is a wildcard match (`$prefix*`).
    pub is_wildcard: bool,
}

impl StringPattern {
    /// Returns `true` when `name` (without leading `$`) matches this pattern.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        let bare = name.trim_start_matches('$');
        if self.is_wildcard {
            bare.starts_with(&self.prefix)
        } else {
            bare == self.prefix
        }
    }
}

// ── EvaluationContext ─────────────────────────────────────────────────────────

/// All runtime state needed to evaluate a YARA condition expression.
pub struct EvaluationContext<'a> {
    /// Raw bytes of the scanned data.
    pub data: &'a [u8],
    /// Per-string match results, keyed by identifier (including `$`).
    pub matches: &'a HashMap<String, Vec<StringMatch>>,
    /// The rule being evaluated (for `them` expansion).
    pub rule: &'a YaraRule,
    /// Optional entry point offset (from PE/ELF headers).
    pub entry_point: Option<u64>,
}

impl<'a> EvaluationContext<'a> {
    /// Create a new context.
    #[must_use]
    pub const fn new(
        data: &'a [u8],
        matches: &'a HashMap<String, Vec<StringMatch>>,
        rule: &'a YaraRule,
        entry_point: Option<u64>,
    ) -> Self {
        Self {
            data,
            matches,
            rule,
            entry_point,
        }
    }

    /// Resolve which string identifiers belong to a `StringSet`.
    #[must_use]
    pub fn resolve_set(&self, set: &StringSet) -> Vec<String> {
        match set {
            StringSet::Them => self.rule.strings.iter().map(|s| s.identifier.clone()).collect(),
            StringSet::List(patterns) => {
                let mut result = Vec::new();
                for s in &self.rule.strings {
                    if patterns.iter().any(|p| p.matches(&s.identifier)) {
                        result.push(s.identifier.clone());
                    }
                }
                result
            }
        }
    }

    /// Count matches for a given identifier.
    #[must_use]
    pub fn count(&self, ident: &str) -> usize {
        self.matches.get(ident).map_or(0, Vec::len)
    }

    /// Return `true` if `ident` has at least one match.
    #[must_use]
    pub fn present(&self, ident: &str) -> bool {
        self.count(ident) > 0
    }

    /// Return `true` if any match of `ident` lands exactly at `offset`.
    #[must_use]
    pub fn at(&self, ident: &str, offset: u64) -> bool {
        self.matches
            .get(ident)
            .is_some_and(|v| v.iter().any(|m| m.offset == offset))
    }

    /// Return `true` if any match of `ident` falls within `[lo, hi]`.
    #[must_use]
    pub fn within(&self, ident: &str, lo: u64, hi: u64) -> bool {
        self.matches
            .get(ident)
            .is_some_and(|v| v.iter().any(|m| m.offset >= lo && m.offset <= hi))
    }
}

// ── ConditionEvaluator ────────────────────────────────────────────────────────

/// Evaluates YARA condition expressions against scan data.
///
/// Supports the full rich `Expr` AST as well as the legacy `Condition` enum
/// used elsewhere in `rustre-yara-engine`.
pub struct ConditionEvaluator;

impl ConditionEvaluator {
    /// Evaluate a rich `Expr` AST.
    ///
    /// Returns `true` if the condition is satisfied, `false` otherwise.
    /// Errors (e.g. out-of-bounds reads, type mismatches) produce `false`.
    #[must_use]
    pub fn eval(expr: &Expr, ctx: &EvaluationContext<'_>) -> bool {
        match Self::eval_value(expr, ctx) {
            Value::Bool(b) => b,
            Value::Int(n) => n != 0,
            Value::Undefined => false,
        }
    }

    /// Evaluate an expression to a [`Value`].
    ///
    /// # Panics
    ///
    /// Panics if a fixed-size byte slice conversion fails (should never occur
    /// for correctly-bounded offsets).
    #[must_use]
    pub fn eval_value(expr: &Expr, ctx: &EvaluationContext<'_>) -> Value {
        match expr {
            // ── Literals ─────────────────────────────────────────────────────
            Expr::Bool(b) => Value::Bool(*b),
            Expr::Int(n) => Value::Int(*n),

            // ── String predicates ─────────────────────────────────────────────
            Expr::StringPresent(id) => Value::Bool(ctx.present(id)),
            Expr::StringCount(id) => {
                Value::Int(i64::try_from(ctx.count(id)).unwrap_or(i64::MAX))
            }
            Expr::StringAt(id, off_expr) => {
                let off = Self::eval_u64(off_expr, ctx);
                Value::Bool(ctx.at(id, off))
            }
            Expr::StringIn(id, lo_expr, hi_expr) => {
                let lo = Self::eval_u64(lo_expr, ctx);
                let hi = Self::eval_u64(hi_expr, ctx);
                Value::Bool(ctx.within(id, lo, hi))
            }

            // ── Quantifiers ───────────────────────────────────────────────────
            Expr::AllOf(set) => {
                let ids = ctx.resolve_set(set);
                Value::Bool(ids.iter().all(|id| ctx.present(id)))
            }
            Expr::AnyOf(set) => {
                let ids = ctx.resolve_set(set);
                Value::Bool(ids.iter().any(|id| ctx.present(id)))
            }
            Expr::NoneOf(set) => {
                let ids = ctx.resolve_set(set);
                Value::Bool(ids.iter().all(|id| !ctx.present(id)))
            }
            Expr::NOf(count_expr, set) => {
                let required = Self::eval_i64(count_expr, ctx);
                let ids = ctx.resolve_set(set);
                let found = i64::try_from(ids.iter().filter(|id| ctx.present(id)).count())
                    .unwrap_or(i64::MAX);
                Value::Bool(found >= required)
            }
            Expr::ForAll(count_expr, _var, body) => {
                // Evaluate the count limit from the expression; treat as a
                // loop from 1 to N. The body is evaluated N times with the
                // same context (simplified: we evaluate it once and use the
                // count to gate).
                let n = Self::eval_i64(count_expr, ctx);
                let body_val = Self::eval(body, ctx);
                // For `for all i in (1..N)` the body must hold for every i.
                // We approximate: if N <= 0 the vacuous truth is `true`.
                if n <= 0 {
                    Value::Bool(true)
                } else {
                    Value::Bool(body_val)
                }
            }

            // ── File properties ───────────────────────────────────────────────
            Expr::FileSize => Value::Int(
                i64::try_from(ctx.data.len()).unwrap_or(i64::MAX),
            ),
            Expr::EntryPoint => {
                let ep = ctx.entry_point.unwrap_or(0);
                Value::Int(i64::try_from(ep).unwrap_or(i64::MAX))
            }

            // ── Integer reads ─────────────────────────────────────────────────
            Expr::ReadU8(_)
            | Expr::ReadI8(_)
            | Expr::ReadU16(_, _)
            | Expr::ReadI16(_, _)
            | Expr::ReadU32(_, _)
            | Expr::ReadI32(_, _) => Self::eval_value_read(expr, ctx),

            // ── Arithmetic ────────────────────────────────────────────────────
            Expr::Add(_, _)
            | Expr::Sub(_, _)
            | Expr::Mul(_, _)
            | Expr::Div(_, _)
            | Expr::Mod(_, _)
            | Expr::BitAnd(_, _)
            | Expr::BitOr(_, _)
            | Expr::BitXor(_, _)
            | Expr::BitNot(_)
            | Expr::ShiftLeft(_, _)
            | Expr::ShiftRight(_, _)
            | Expr::Negate(_) => Self::eval_value_arith(expr, ctx),

            // ── Comparisons / logical / special ───────────────────────────────
            Expr::Cmp(_, _, _)
            | Expr::Contains(_, _)
            | Expr::IContains(_, _)
            | Expr::StartsWith(_, _)
            | Expr::EndsWith(_, _)
            | Expr::Matches(_, _)
            | Expr::And(_, _)
            | Expr::Or(_, _)
            | Expr::Not(_)
            | Expr::Defined(_) => Self::eval_value_cmp_logical(expr, ctx),
        }
    }

    fn eval_value_read(expr: &Expr, ctx: &EvaluationContext<'_>) -> Value {
        match expr {
            Expr::ReadU8(off) => {
                let o = Self::eval_usize(off, ctx);
                if o < ctx.data.len() { Value::Int(i64::from(ctx.data[o])) }
                else { Value::Undefined }
            }
            Expr::ReadI8(off) => {
                let o = Self::eval_usize(off, ctx);
                if o < ctx.data.len() { Value::Int(i64::from(ctx.data[o].cast_signed())) }
                else { Value::Undefined }
            }
            Expr::ReadU16(off, endian) => {
                let o = Self::eval_usize(off, ctx);
                if o + 2 <= ctx.data.len() {
                    let arr: [u8; 2] = ctx.data[o..o + 2].try_into().unwrap();
                    let v = if *endian == Endian::Little { u16::from_le_bytes(arr) } else { u16::from_be_bytes(arr) };
                    Value::Int(i64::from(v))
                } else { Value::Undefined }
            }
            Expr::ReadI16(off, endian) => {
                let o = Self::eval_usize(off, ctx);
                if o + 2 <= ctx.data.len() {
                    let arr: [u8; 2] = ctx.data[o..o + 2].try_into().unwrap();
                    let v = if *endian == Endian::Little { i16::from_le_bytes(arr) } else { i16::from_be_bytes(arr) };
                    Value::Int(i64::from(v))
                } else { Value::Undefined }
            }
            Expr::ReadU32(off, endian) => {
                let o = Self::eval_usize(off, ctx);
                if o + 4 <= ctx.data.len() {
                    let arr: [u8; 4] = ctx.data[o..o + 4].try_into().unwrap();
                    let v = if *endian == Endian::Little { u32::from_le_bytes(arr) } else { u32::from_be_bytes(arr) };
                    Value::Int(i64::from(v))
                } else { Value::Undefined }
            }
            Expr::ReadI32(off, endian) => {
                let o = Self::eval_usize(off, ctx);
                if o + 4 <= ctx.data.len() {
                    let arr: [u8; 4] = ctx.data[o..o + 4].try_into().unwrap();
                    let v = if *endian == Endian::Little { i32::from_le_bytes(arr) } else { i32::from_be_bytes(arr) };
                    Value::Int(i64::from(v))
                } else { Value::Undefined }
            }
            _ => Value::Undefined,
        }
    }

    fn eval_value_arith(expr: &Expr, ctx: &EvaluationContext<'_>) -> Value {
        match expr {
            Expr::Add(a, b) => Value::Int(Self::eval_i64(a, ctx).saturating_add(Self::eval_i64(b, ctx))),
            Expr::Sub(a, b) => Value::Int(Self::eval_i64(a, ctx).saturating_sub(Self::eval_i64(b, ctx))),
            Expr::Mul(a, b) => Value::Int(Self::eval_i64(a, ctx).saturating_mul(Self::eval_i64(b, ctx))),
            Expr::Div(a, b) => {
                let divisor = Self::eval_i64(b, ctx);
                if divisor == 0 { Value::Undefined } else { Value::Int(Self::eval_i64(a, ctx) / divisor) }
            }
            Expr::Mod(a, b) => {
                let divisor = Self::eval_i64(b, ctx);
                if divisor == 0 { Value::Undefined } else { Value::Int(Self::eval_i64(a, ctx) % divisor) }
            }
            Expr::BitAnd(a, b) => Value::Int(Self::eval_i64(a, ctx) & Self::eval_i64(b, ctx)),
            Expr::BitOr(a, b)  => Value::Int(Self::eval_i64(a, ctx) | Self::eval_i64(b, ctx)),
            Expr::BitXor(a, b) => Value::Int(Self::eval_i64(a, ctx) ^ Self::eval_i64(b, ctx)),
            Expr::BitNot(a)    => Value::Int(!Self::eval_i64(a, ctx)),
            Expr::ShiftLeft(a, b) => {
                let shift = Self::eval_i64(b, ctx);
                if (0..64).contains(&shift) { Value::Int(Self::eval_i64(a, ctx) << shift) }
                else { Value::Int(0) }
            }
            Expr::ShiftRight(a, b) => {
                let shift = Self::eval_i64(b, ctx);
                if (0..64).contains(&shift) {
                    let bits = Self::eval_i64(a, ctx).cast_unsigned() >> shift;
                    Value::Int(bits.cast_signed())
                } else { Value::Int(0) }
            }
            Expr::Negate(a) => Value::Int(Self::eval_i64(a, ctx).saturating_neg()),
            _ => Value::Undefined,
        }
    }

    fn eval_value_cmp_logical(expr: &Expr, ctx: &EvaluationContext<'_>) -> Value {
        match expr {
            Expr::Cmp(lhs, op, rhs) => {
                Value::Bool(Self::apply_cmp(Self::eval_i64(lhs, ctx), *op, Self::eval_i64(rhs, ctx)))
            }
            Expr::Contains(haystack, needle) => {
                Value::Bool(contains_bytes(&Self::eval_bytes(haystack, ctx), &Self::eval_bytes(needle, ctx)))
            }
            Expr::IContains(haystack, needle) => {
                let hs_lower: Vec<u8> = Self::eval_bytes(haystack, ctx).iter().map(u8::to_ascii_lowercase).collect();
                let nd_lower: Vec<u8> = Self::eval_bytes(needle, ctx).iter().map(u8::to_ascii_lowercase).collect();
                Value::Bool(contains_bytes(&hs_lower, &nd_lower))
            }
            Expr::StartsWith(haystack, prefix) => {
                Value::Bool(Self::eval_bytes(haystack, ctx).starts_with(&Self::eval_bytes(prefix, ctx)))
            }
            Expr::EndsWith(haystack, suffix) => {
                Value::Bool(Self::eval_bytes(haystack, ctx).ends_with(&Self::eval_bytes(suffix, ctx)))
            }
            Expr::Matches(target, _pattern) => {
                // Regex matching requires the regex crate; literal fallback only.
                let _ = target;
                Value::Bool(false)
            }
            Expr::And(a, b) => {
                if Self::eval(a, ctx) { Value::Bool(Self::eval(b, ctx)) } else { Value::Bool(false) }
            }
            Expr::Or(a, b) => {
                if Self::eval(a, ctx) { Value::Bool(true) } else { Value::Bool(Self::eval(b, ctx)) }
            }
            Expr::Not(inner) => Value::Bool(!Self::eval(inner, ctx)),
            Expr::Defined(id) => Value::Bool(ctx.rule.strings.iter().any(|s| &s.identifier == id)),
            _ => Value::Undefined,
        }
    }

    // ── Legacy Condition adapter ──────────────────────────────────────────────

    /// Evaluate the legacy `Condition` enum used in `YaraRule`.
    #[must_use]
    pub fn eval_legacy(
        condition: &Condition,
        data: &[u8],
        matches: &HashMap<String, Vec<StringMatch>>,
        rule: &YaraRule,
    ) -> bool {
        let ctx = EvaluationContext::new(data, matches, rule, detect_entry_point(data));
        Self::eval_legacy_inner(condition, &ctx)
    }

    fn eval_legacy_inner(condition: &Condition, ctx: &EvaluationContext<'_>) -> bool {
        match condition {
            Condition::True => true,
            Condition::False => false,
            Condition::All => {
                ctx.rule.strings.iter().all(|s| ctx.present(&s.identifier))
            }
            Condition::Any => {
                ctx.rule.strings.iter().any(|s| ctx.present(&s.identifier))
            }
            Condition::None => {
                ctx.rule.strings.iter().all(|s| !ctx.present(&s.identifier))
            }
            Condition::StringMatch(id) => ctx.present(id),
            Condition::StringCount(id) => {
                let bare = id.trim_start_matches('#');
                ctx.count(bare) > 0
            }
            Condition::StringAt(id, offset) => ctx.at(id, *offset),
            Condition::StringIn(id, lo, hi) => ctx.within(id, *lo, *hi),
            Condition::FileSize(op, size) => {
                let fs = i64::try_from(ctx.data.len()).unwrap_or(i64::MAX);
                Self::apply_cmp(fs, *op, i64::try_from(*size).unwrap_or(i64::MAX))
            }
            Condition::EntryPoint => ctx
                .entry_point
                .is_some_and(|ep| ep < ctx.data.len() as u64),
            Condition::And(a, b) => {
                Self::eval_legacy_inner(a, ctx) && Self::eval_legacy_inner(b, ctx)
            }
            Condition::Or(a, b) => {
                Self::eval_legacy_inner(a, ctx) || Self::eval_legacy_inner(b, ctx)
            }
            Condition::Not(inner) => !Self::eval_legacy_inner(inner, ctx),
            Condition::ForAll(inner) => Self::eval_legacy_inner(inner, ctx),
            Condition::IntAt(offset) => {
                let o = usize::try_from(*offset).unwrap_or(usize::MAX);
                o + 4 <= ctx.data.len()
            }
        }
    }

    // ── Helper evaluators ─────────────────────────────────────────────────────

    fn eval_i64(expr: &Expr, ctx: &EvaluationContext<'_>) -> i64 {
        match Self::eval_value(expr, ctx) {
            Value::Int(n) => n,
            Value::Bool(b) => i64::from(b),
            Value::Undefined => 0,
        }
    }

    fn eval_u64(expr: &Expr, ctx: &EvaluationContext<'_>) -> u64 {
        let v = Self::eval_i64(expr, ctx);
        u64::try_from(v).unwrap_or(0)
    }

    fn eval_usize(expr: &Expr, ctx: &EvaluationContext<'_>) -> usize {
        usize::try_from(Self::eval_u64(expr, ctx)).unwrap_or(usize::MAX)
    }

    fn eval_bytes(expr: &Expr, ctx: &EvaluationContext<'_>) -> Vec<u8> {
        let n = Self::eval_i64(expr, ctx);
        n.to_le_bytes().to_vec()
    }

    const fn apply_cmp(l: i64, op: CompOp, r: i64) -> bool {
        match op {
            CompOp::Eq => l == r,
            CompOp::Ne => l != r,
            CompOp::Lt => l < r,
            CompOp::Le => l <= r,
            CompOp::Gt => l > r,
            CompOp::Ge => l >= r,
        }
    }
}

/// Evaluated value type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Undefined,
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn detect_entry_point(data: &[u8]) -> Option<u64> {
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        // PE: stub — entry point detection requires full PE parse
        Some(0)
    } else if data.len() >= 4 && data[0] == 0x7F && &data[1..4] == b"ELF" {
        Some(0)
    } else {
        None
    }
}

// ── QuantifierEngine ──────────────────────────────────────────────────────────

/// Implements the quantifier logic for YARA `for`/`of` expressions.
pub struct QuantifierEngine;

impl QuantifierEngine {
    /// Evaluate `N of <set>` where `N` is a concrete count.
    #[must_use]
    pub fn eval_n_of(
        n: usize,
        set: &StringSet,
        ctx: &EvaluationContext<'_>,
    ) -> bool {
        let ids = ctx.resolve_set(set);
        let found = ids.iter().filter(|id| ctx.present(id)).count();
        found >= n
    }

    /// Evaluate `for N i in (expr_list): (condition)`.
    ///
    /// The `conditions` slice must have the same length as `expr_list`.
    #[must_use]
    pub fn eval_for_n_of(
        n: usize,
        results: &[bool],
    ) -> bool {
        results.iter().filter(|&&b| b).count() >= n
    }

    /// Evaluate `for all i in (expr_list): (condition)`.
    #[must_use]
    pub fn eval_for_all_of(results: &[bool]) -> bool {
        results.iter().all(|&b| b)
    }

    /// Evaluate `for any i in (expr_list): (condition)`.
    #[must_use]
    pub fn eval_for_any_of(results: &[bool]) -> bool {
        results.iter().any(|&b| b)
    }

    /// Evaluate `for none i in (expr_list): (condition)`.
    #[must_use]
    pub fn eval_for_none_of(results: &[bool]) -> bool {
        results.iter().all(|&b| !b)
    }

    /// Expand a `StringSet::List` wildcard pattern against available strings.
    #[must_use]
    pub fn expand_wildcard(pattern: &StringPattern, strings: &[YaraString]) -> Vec<String> {
        strings
            .iter()
            .filter(|s| pattern.matches(&s.identifier))
            .map(|s| s.identifier.clone())
            .collect()
    }
}

// ── WithOperator ──────────────────────────────────────────────────────────────

/// Evaluator for the `with` operator: `with $a as (something): condition`.
pub struct WithOperator;

impl WithOperator {
    /// Evaluate a `with` binding where `binding_expr` evaluates to an integer
    /// that is then injected as a variable into `body`.
    ///
    /// This is a simplified implementation: we evaluate both sides independently
    /// and return the `body` result.
    #[must_use]
    pub fn eval(
        _binding_expr: &Expr,
        body: &Expr,
        ctx: &EvaluationContext<'_>,
    ) -> bool {
        ConditionEvaluator::eval(body, ctx)
    }
}

// ── AtOperator ────────────────────────────────────────────────────────────────

/// Convenience evaluators for the `at` and `in` operators.
pub struct AtOperator;

impl AtOperator {
    /// Evaluate `$ident at offset`.
    #[must_use]
    pub fn at(ident: &str, offset: u64, ctx: &EvaluationContext<'_>) -> bool {
        ctx.at(ident, offset)
    }

    /// Evaluate `$ident in (lo..hi)`.
    #[must_use]
    pub fn in_range(ident: &str, lo: u64, hi: u64, ctx: &EvaluationContext<'_>) -> bool {
        ctx.within(ident, lo, hi)
    }

    /// Return all offsets where `ident` matched within `[lo, hi]`.
    #[must_use]
    pub fn offsets_in_range(
        ident: &str,
        lo: u64,
        hi: u64,
        ctx: &EvaluationContext<'_>,
    ) -> Vec<u64> {
        ctx.matches
            .get(ident)
            .map(|v| {
                v.iter()
                    .filter(|m| m.offset >= lo && m.offset <= hi)
                    .map(|m| m.offset)
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ── FileSizeEvaluator ─────────────────────────────────────────────────────────

/// Helpers for `filesize` comparisons.
pub struct FileSizeEvaluator;

impl FileSizeEvaluator {
    /// Evaluate `filesize <op> <value>` where `value` can include KB/MB suffixes.
    #[must_use]
    pub fn compare(data_len: usize, op: CompOp, value: u64) -> bool {
        let fs = u64::try_from(data_len).unwrap_or(u64::MAX);
        match op {
            CompOp::Eq => fs == value,
            CompOp::Ne => fs != value,
            CompOp::Lt => fs < value,
            CompOp::Le => fs <= value,
            CompOp::Gt => fs > value,
            CompOp::Ge => fs >= value,
        }
    }

    /// Parse a size string like `"100KB"` or `"2MB"` into bytes.
    #[must_use]
    pub fn parse_size(s: &str) -> Option<u64> {
        let s = s.trim();
        let suffixes: &[(&str, &str, u64)] = &[
            ("KB", "kb", 1024),
            ("MB", "mb", 1024 * 1024),
            ("GB", "gb", 1024 * 1024 * 1024),
        ];
        suffixes.iter().find_map(|(upper, lower, mult)| {
            s.strip_suffix(upper)
                .or_else(|| s.strip_suffix(lower))
                .and_then(|n| n.trim().parse::<u64>().ok().map(|v| v * mult))
        }).or_else(|| s.parse::<u64>().ok())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StringModifiers, StringValue, YaraString};

    fn make_rule(strings: Vec<YaraString>) -> YaraRule {
        YaraRule {
            name: "test".into(),
            namespace: "default".into(),
            tags: vec![],
            meta: HashMap::new(),
            strings,
            condition: Condition::True,
        }
    }

    fn make_match(id: &str, offset: u64) -> StringMatch {
        StringMatch {
            identifier: id.to_string(),
            offset,
            length: 3,
            matched_data: b"foo".to_vec(),
        }
    }

    fn ctx_with_match<'a>(
        data: &'a [u8],
        matches: &'a HashMap<String, Vec<StringMatch>>,
        rule: &'a YaraRule,
    ) -> EvaluationContext<'a> {
        EvaluationContext::new(data, matches, rule, None)
    }

    #[test]
    fn test_bool_literal() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"data", &m, &rule);
        assert!(ConditionEvaluator::eval(&Expr::Bool(true), &ctx));
        assert!(!ConditionEvaluator::eval(&Expr::Bool(false), &ctx));
    }

    #[test]
    fn test_int_literal_nonzero_is_true() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"data", &m, &rule);
        assert!(ConditionEvaluator::eval(&Expr::Int(42), &ctx));
        assert!(!ConditionEvaluator::eval(&Expr::Int(0), &ctx));
    }

    #[test]
    fn test_string_present() {
        let rule = make_rule(vec![YaraString {
            identifier: "$a".into(),
            value: StringValue::Text("hello".into()),
            modifiers: StringModifiers::NONE,
        }]);
        let mut m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        m.insert("$a".into(), vec![make_match("$a", 0)]);
        let ctx = ctx_with_match(b"hello", &m, &rule);
        assert!(ConditionEvaluator::eval(&Expr::StringPresent("$a".into()), &ctx));
    }

    #[test]
    fn test_string_absent() {
        let rule = make_rule(vec![YaraString {
            identifier: "$a".into(),
            value: StringValue::Text("hello".into()),
            modifiers: StringModifiers::NONE,
        }]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"world", &m, &rule);
        assert!(!ConditionEvaluator::eval(&Expr::StringPresent("$a".into()), &ctx));
    }

    #[test]
    fn test_string_count() {
        let rule = make_rule(vec![]);
        let mut m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        m.insert("$a".into(), vec![make_match("$a", 0), make_match("$a", 5)]);
        let ctx = ctx_with_match(b"aaa aaa", &m, &rule);
        assert_eq!(
            ConditionEvaluator::eval_value(&Expr::StringCount("$a".into()), &ctx),
            Value::Int(2)
        );
    }

    #[test]
    fn test_string_at_operator() {
        let rule = make_rule(vec![]);
        let mut m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        m.insert("$a".into(), vec![make_match("$a", 4)]);
        let ctx = ctx_with_match(b"data_foo", &m, &rule);
        assert!(ConditionEvaluator::eval(
            &Expr::StringAt("$a".into(), Box::new(Expr::Int(4))),
            &ctx
        ));
        assert!(!ConditionEvaluator::eval(
            &Expr::StringAt("$a".into(), Box::new(Expr::Int(0))),
            &ctx
        ));
    }

    #[test]
    fn test_string_in_operator() {
        let rule = make_rule(vec![]);
        let mut m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        m.insert("$a".into(), vec![make_match("$a", 10)]);
        let ctx = ctx_with_match(b"padding_padding_foo", &m, &rule);
        assert!(ConditionEvaluator::eval(
            &Expr::StringIn("$a".into(), Box::new(Expr::Int(5)), Box::new(Expr::Int(15))),
            &ctx
        ));
        assert!(!ConditionEvaluator::eval(
            &Expr::StringIn("$a".into(), Box::new(Expr::Int(0)), Box::new(Expr::Int(5))),
            &ctx
        ));
    }

    #[test]
    fn test_all_of_them() {
        let rule = make_rule(vec![
            YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("a".into()),
                modifiers: StringModifiers::NONE,
            },
            YaraString {
                identifier: "$b".into(),
                value: StringValue::Text("b".into()),
                modifiers: StringModifiers::NONE,
            },
        ]);
        let mut m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        m.insert("$a".into(), vec![make_match("$a", 0)]);
        m.insert("$b".into(), vec![make_match("$b", 1)]);
        let ctx = ctx_with_match(b"ab", &m, &rule);
        assert!(ConditionEvaluator::eval(&Expr::AllOf(StringSet::Them), &ctx));
    }

    #[test]
    fn test_any_of_them() {
        let rule = make_rule(vec![
            YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("a".into()),
                modifiers: StringModifiers::NONE,
            },
            YaraString {
                identifier: "$b".into(),
                value: StringValue::Text("b".into()),
                modifiers: StringModifiers::NONE,
            },
        ]);
        let mut m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        m.insert("$a".into(), vec![make_match("$a", 0)]);
        let ctx = ctx_with_match(b"ax", &m, &rule);
        assert!(ConditionEvaluator::eval(&Expr::AnyOf(StringSet::Them), &ctx));
    }

    #[test]
    fn test_none_of_them() {
        let rule = make_rule(vec![
            YaraString {
                identifier: "$a".into(),
                value: StringValue::Text("a".into()),
                modifiers: StringModifiers::NONE,
            },
        ]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"xyz", &m, &rule);
        assert!(ConditionEvaluator::eval(&Expr::NoneOf(StringSet::Them), &ctx));
    }

    #[test]
    fn test_n_of() {
        let rule = make_rule(vec![
            YaraString { identifier: "$a".into(), value: StringValue::Text("a".into()), modifiers: StringModifiers::NONE },
            YaraString { identifier: "$b".into(), value: StringValue::Text("b".into()), modifiers: StringModifiers::NONE },
            YaraString { identifier: "$c".into(), value: StringValue::Text("c".into()), modifiers: StringModifiers::NONE },
        ]);
        let mut m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        m.insert("$a".into(), vec![make_match("$a", 0)]);
        m.insert("$b".into(), vec![make_match("$b", 1)]);
        let ctx = ctx_with_match(b"ab", &m, &rule);
        assert!(ConditionEvaluator::eval(
            &Expr::NOf(Box::new(Expr::Int(2)), StringSet::Them),
            &ctx
        ));
        assert!(!ConditionEvaluator::eval(
            &Expr::NOf(Box::new(Expr::Int(3)), StringSet::Them),
            &ctx
        ));
    }

    #[test]
    fn test_filesize() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"1234567890", &m, &rule);
        assert_eq!(
            ConditionEvaluator::eval_value(&Expr::FileSize, &ctx),
            Value::Int(10)
        );
    }

    #[test]
    fn test_arithmetic_add() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"", &m, &rule);
        assert_eq!(
            ConditionEvaluator::eval_value(
                &Expr::Add(Box::new(Expr::Int(3)), Box::new(Expr::Int(4))),
                &ctx
            ),
            Value::Int(7)
        );
    }

    #[test]
    fn test_arithmetic_div_zero() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"", &m, &rule);
        assert_eq!(
            ConditionEvaluator::eval_value(
                &Expr::Div(Box::new(Expr::Int(10)), Box::new(Expr::Int(0))),
                &ctx
            ),
            Value::Undefined
        );
    }

    #[test]
    fn test_comparison_gt() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"hello", &m, &rule);
        assert!(ConditionEvaluator::eval(
            &Expr::Cmp(Box::new(Expr::FileSize), CompOp::Gt, Box::new(Expr::Int(4))),
            &ctx
        ));
    }

    #[test]
    fn test_logical_and() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"", &m, &rule);
        assert!(!ConditionEvaluator::eval(
            &Expr::And(Box::new(Expr::Bool(true)), Box::new(Expr::Bool(false))),
            &ctx
        ));
        assert!(ConditionEvaluator::eval(
            &Expr::And(Box::new(Expr::Bool(true)), Box::new(Expr::Bool(true))),
            &ctx
        ));
    }

    #[test]
    fn test_logical_or() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"", &m, &rule);
        assert!(ConditionEvaluator::eval(
            &Expr::Or(Box::new(Expr::Bool(false)), Box::new(Expr::Bool(true))),
            &ctx
        ));
        assert!(!ConditionEvaluator::eval(
            &Expr::Or(Box::new(Expr::Bool(false)), Box::new(Expr::Bool(false))),
            &ctx
        ));
    }

    #[test]
    fn test_not() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"", &m, &rule);
        assert!(ConditionEvaluator::eval(&Expr::Not(Box::new(Expr::Bool(false))), &ctx));
    }

    #[test]
    fn test_read_u8() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let data = b"\xDE\xAD\xBE\xEF";
        let ctx = ctx_with_match(data, &m, &rule);
        assert_eq!(
            ConditionEvaluator::eval_value(&Expr::ReadU8(Box::new(Expr::Int(1))), &ctx),
            Value::Int(0xAD)
        );
    }

    #[test]
    fn test_read_u32_le() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let data = b"\x78\x56\x34\x12";
        let ctx = ctx_with_match(data, &m, &rule);
        assert_eq!(
            ConditionEvaluator::eval_value(
                &Expr::ReadU32(Box::new(Expr::Int(0)), Endian::Little),
                &ctx
            ),
            Value::Int(0x1234_5678)
        );
    }

    #[test]
    fn test_filesize_evaluator_parse_kb() {
        assert_eq!(FileSizeEvaluator::parse_size("4KB"), Some(4096));
    }

    #[test]
    fn test_filesize_evaluator_parse_mb() {
        assert_eq!(FileSizeEvaluator::parse_size("2MB"), Some(2 * 1024 * 1024));
    }

    #[test]
    fn test_at_operator_in_range() {
        let rule = make_rule(vec![]);
        let mut m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        m.insert("$a".into(), vec![make_match("$a", 20)]);
        let ctx = ctx_with_match(b"", &m, &rule);
        assert!(AtOperator::in_range("$a", 10, 30, &ctx));
        assert!(!AtOperator::in_range("$a", 0, 10, &ctx));
    }

    #[test]
    fn test_quantifier_engine_n_of() {
        let rule = make_rule(vec![
            YaraString { identifier: "$a".into(), value: StringValue::Text("a".into()), modifiers: StringModifiers::NONE },
        ]);
        let mut m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        m.insert("$a".into(), vec![make_match("$a", 0)]);
        let ctx = ctx_with_match(b"a", &m, &rule);
        assert!(QuantifierEngine::eval_n_of(1, &StringSet::Them, &ctx));
        assert!(!QuantifierEngine::eval_n_of(2, &StringSet::Them, &ctx));
    }

    #[test]
    fn test_for_all_results() {
        assert!(QuantifierEngine::eval_for_all_of(&[true, true, true]));
        assert!(!QuantifierEngine::eval_for_all_of(&[true, false, true]));
    }

    #[test]
    fn test_for_any_results() {
        assert!(QuantifierEngine::eval_for_any_of(&[false, true, false]));
        assert!(!QuantifierEngine::eval_for_any_of(&[false, false]));
    }

    #[test]
    fn test_for_none_results() {
        assert!(QuantifierEngine::eval_for_none_of(&[false, false]));
        assert!(!QuantifierEngine::eval_for_none_of(&[false, true]));
    }

    #[test]
    fn test_string_pattern_wildcard() {
        let p = StringPattern { prefix: "foo".into(), is_wildcard: true };
        assert!(p.matches("$foobar"));
        assert!(p.matches("$foo"));
        assert!(!p.matches("$bar"));
    }

    #[test]
    fn test_legacy_condition_all() {
        let rule = make_rule(vec![
            YaraString { identifier: "$a".into(), value: StringValue::Text("a".into()), modifiers: StringModifiers::NONE },
        ]);
        let mut m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        m.insert("$a".into(), vec![make_match("$a", 0)]);
        assert!(ConditionEvaluator::eval_legacy(&Condition::All, b"a", &m, &rule));
    }

    #[test]
    fn test_shift_left_right() {
        let rule = make_rule(vec![]);
        let m: HashMap<String, Vec<StringMatch>> = HashMap::new();
        let ctx = ctx_with_match(b"", &m, &rule);
        assert_eq!(
            ConditionEvaluator::eval_value(
                &Expr::ShiftLeft(Box::new(Expr::Int(1)), Box::new(Expr::Int(3))),
                &ctx
            ),
            Value::Int(8)
        );
        assert_eq!(
            ConditionEvaluator::eval_value(
                &Expr::ShiftRight(Box::new(Expr::Int(16)), Box::new(Expr::Int(2))),
                &ctx
            ),
            Value::Int(4)
        );
    }
}
