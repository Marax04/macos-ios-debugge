// condition_expr_eval.rs — YARA condition expression evaluator
// Evaluates the boolean condition of a YARA rule against a scan context.

use std::collections::HashMap;

use num_traits::ToPrimitive as _;

/// Saturating f64 → i64 conversion (NaN → 0, overflow → `i64::MAX`/`i64::MIN`).
fn f64_saturate_to_i64(f: f64) -> i64 {
    const MAX_F64: f64 = 9_223_372_036_854_775_808.0_f64; // 2^63
    const MIN_F64: f64 = -9_223_372_036_854_775_808.0_f64; // -2^63
    if f.is_nan() { 0 }
    else if f >= MAX_F64 { i64::MAX }
    else if f <= MIN_F64 { i64::MIN }
    else {
        // f is finite and bounded within i64 range; ToPrimitive::to_i64 is a
        // lossless, safe conversion that clippy accepts without any allow attrs.
        f.to_i64().unwrap_or(0)
    }
}

macro_rules! try_opt {
    ($expr:expr) => {
        match $expr {
            Some(val) => val,
            None => return EvalResult::Undefined,
        }
    };
}

// ---------------------------------------------------------------------------
// Evaluation context
// ---------------------------------------------------------------------------

/// Holds all state needed to evaluate a YARA condition.
#[derive(Debug, Default)]
pub struct EvalContext {
    /// Map from string identifier (e.g. "$a") to list of match offsets.
    pub string_matches: HashMap<String, Vec<u64>>,
    /// File size in bytes.
    pub file_size: u64,
    /// Entry point of the binary (PE/ELF), `u64::MAX` if not available.
    pub entry_point: u64,
    /// Module data: map from module name to key-value pairs.
    pub module_data: HashMap<String, HashMap<String, ModuleValue>>,
    /// Integer variables set by `for` loops or external definitions.
    pub int_vars: HashMap<String, i64>,
    /// Boolean variables.
    pub bool_vars: HashMap<String, bool>,
}

impl EvalContext {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            entry_point: u64::MAX,
            ..Default::default()
        }
    }

    /// Record matches for a string identifier.
    pub fn add_matches(&mut self, id: &str, offsets: Vec<u64>) {
        self.string_matches.insert(id.to_string(), offsets);
    }

    /// Return true if string `id` has at least one match.
    #[must_use] 
    pub fn string_matched(&self, id: &str) -> bool {
        self.string_matches.get(id).is_some_and(|v| !v.is_empty())
    }

    /// Return the number of matches for string `id`.
    #[must_use] 
    pub fn string_count(&self, id: &str) -> u64 {
        self.string_matches.get(id).map_or(0, |v| v.len() as u64)
    }

    /// Return true if string `id` matches at `offset`.
    #[must_use] 
    pub fn string_at(&self, id: &str, offset: u64) -> bool {
        self.string_matches
            .get(id)
            .is_some_and(|v| v.contains(&offset))
    }

    /// Return true if string `id` has a match in [from, to].
    #[must_use] 
    pub fn string_in(&self, id: &str, from: u64, to: u64) -> bool {
        self.string_matches
            .get(id)
            .is_some_and(|v| v.iter().any(|&off| off >= from && off <= to))
    }
}

// ---------------------------------------------------------------------------
// Module value
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ModuleValue {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Bytes(Vec<u8>),
}

impl ModuleValue {
    #[must_use] 
    pub const fn as_int(&self) -> Option<i64> {
        match self { Self::Int(i) => Some(*i), _ => None }
    }

    #[must_use] 
    pub const fn as_bool(&self) -> Option<bool> {
        match self { Self::Bool(b) => Some(*b), _ => None }
    }
}

// ---------------------------------------------------------------------------
// Condition expression AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ConditionExpr {
    // --- Literals ---
    True,
    False,
    Int(i64),
    Float(f64),
    Str(String),

    // --- String references ---
    /// `$s` — true if matched at least once
    StringMatch(String),
    /// `#s` — match count
    StringCount(String),
    /// `$s at <expr>` — matched at offset
    StringAt { id: String, offset: Box<Self> },
    /// `$s in (<from>..<to>)` — matched in range
    StringIn { id: String, from: Box<Self>, to: Box<Self> },

    // --- Wildcards ---
    /// `any of ($a, $b, ...)` or `any of them`
    AnyOf(Vec<String>),
    /// `all of ($a, $b, ...)`
    AllOf(Vec<String>),
    /// `none of ($a, $b, ...)`
    NoneOf(Vec<String>),
    /// `N of ($a, $b, ...)`
    NOf { n: Box<Self>, ids: Vec<String> },

    // --- File properties ---
    /// `filesize`
    Filesize,
    /// `entrypoint`
    Entrypoint,

    // --- Arithmetic ---
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Div(Box<Self>, Box<Self>),
    Mod(Box<Self>, Box<Self>),
    BitAnd(Box<Self>, Box<Self>),
    BitOr(Box<Self>, Box<Self>),
    BitXor(Box<Self>, Box<Self>),
    BitNot(Box<Self>),
    Shl(Box<Self>, Box<Self>),
    Shr(Box<Self>, Box<Self>),
    Neg(Box<Self>),

    // --- Comparison ---
    Eq(Box<Self>, Box<Self>),
    Ne(Box<Self>, Box<Self>),
    Lt(Box<Self>, Box<Self>),
    Le(Box<Self>, Box<Self>),
    Gt(Box<Self>, Box<Self>),
    Ge(Box<Self>, Box<Self>),
    Contains(Box<Self>, Box<Self>),
    IContains(Box<Self>, Box<Self>),
    StartsWith(Box<Self>, Box<Self>),
    EndsWith(Box<Self>, Box<Self>),
    Matches(Box<Self>, String), // regex

    // --- Boolean ---
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),

    // --- For loops ---
    /// `for any/all/N of <set>: (<condition>)`
    ForOf {
        quantifier: Quantifier,
        ids: Vec<String>,
        body: Box<Self>,
    },

    // --- Module field access ---
    /// `pe.imphash()`  — represented as module.field
    ModuleField { module: String, field: String },

    // --- Variable reference ---
    Var(String),

    // --- Integer functions ---
    /// `uint8(offset)`, `uint16(offset)`, etc.
    IntFunc { func: IntFunc, offset: Box<Self> },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Quantifier {
    Any,
    All,
    None,
    N(Box<ConditionExpr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntFunc {
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Int8,
    Int16,
    Int32,
    Int64,
    Uint8Be,
    Uint16Be,
    Uint32Be,
    Uint64Be,
}

// ---------------------------------------------------------------------------
// Evaluation result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum EvalResult {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Undefined,
}

impl EvalResult {
    #[must_use] 
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            Self::Int(i)  => Some(*i != 0),
            _                   => None,
        }
    }

    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i)   => Some(*i),
            Self::Float(f) => Some(f64_saturate_to_i64(*f)),
            _                    => None,
        }
    }

    #[must_use] 
    pub const fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }

    const fn bool(b: bool) -> Self { Self::Bool(b) }
    const fn int(i: i64) -> Self { Self::Int(i) }
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ConditionEvaluator {
    /// Raw file bytes for uint*/int* functions.
    pub file_bytes: Vec<u8>,
}

impl ConditionEvaluator {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn with_file_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.file_bytes = bytes;
        self
    }

    /// Evaluate `expr` in `ctx`. Returns `EvalResult`.
    #[must_use]
    pub fn eval(&self, expr: &ConditionExpr, ctx: &EvalContext) -> EvalResult {
        if let Some(r) = self.eval_literals_and_strings(expr, ctx) { return r; }
        self.eval_arith_cmp_misc(expr, ctx)
    }

    /// Evaluates literal values, string queries, and set operators.
    fn eval_literals_and_strings(&self, expr: &ConditionExpr, ctx: &EvalContext) -> Option<EvalResult> {
        let r = match expr {
            ConditionExpr::True        => EvalResult::Bool(true),
            ConditionExpr::False       => EvalResult::Bool(false),
            ConditionExpr::Int(i)      => EvalResult::Int(*i),
            ConditionExpr::Float(f)    => EvalResult::Float(*f),
            ConditionExpr::Str(s)      => EvalResult::Str(s.clone()),
            ConditionExpr::StringMatch(id) => EvalResult::bool(ctx.string_matched(id)),
            ConditionExpr::StringCount(id) => EvalResult::int(ctx.string_count(id).cast_signed()),
            ConditionExpr::StringAt { id, offset } => {
                let off = match self.eval(offset, ctx).as_int() {
                    Some(i) if i >= 0 => i.cast_unsigned(),
                    _ => return Some(EvalResult::Undefined),
                };
                EvalResult::bool(ctx.string_at(id, off))
            }
            ConditionExpr::StringIn { id, from, to } => {
                let f = match self.eval(from, ctx).as_int() {
                    Some(i) if i >= 0 => i.cast_unsigned(),
                    _ => return Some(EvalResult::Undefined),
                };
                let t = match self.eval(to, ctx).as_int() {
                    Some(i) if i >= 0 => i.cast_unsigned(),
                    _ => return Some(EvalResult::Undefined),
                };
                EvalResult::bool(ctx.string_in(id, f, t))
            }
            ConditionExpr::AnyOf(ids)  => EvalResult::bool(ids.iter().any(|id| ctx.string_matched(id))),
            ConditionExpr::AllOf(ids)  => EvalResult::bool(ids.iter().all(|id| ctx.string_matched(id))),
            ConditionExpr::NoneOf(ids) => EvalResult::bool(ids.iter().all(|id| !ctx.string_matched(id))),
            ConditionExpr::NOf { n, ids } => {
                let Some(count) = self.eval(n, ctx).as_int() else { return Some(EvalResult::Undefined); };
                let matched = i64::try_from(ids.iter().filter(|id| ctx.string_matched(id)).count()).unwrap_or(i64::MAX);
                EvalResult::bool(matched >= count)
            }
            ConditionExpr::Filesize   => EvalResult::int(ctx.file_size.cast_signed()),
            ConditionExpr::Entrypoint => {
                if ctx.entry_point == u64::MAX { EvalResult::Undefined }
                else { EvalResult::int(ctx.entry_point.cast_signed()) }
            }
            _ => return None,
        };
        Some(r)
    }

    /// Evaluates arithmetic, comparison, boolean, and miscellaneous expressions.
    fn eval_arith_cmp_misc(&self, expr: &ConditionExpr, ctx: &EvalContext) -> EvalResult {
        match expr {
            ConditionExpr::Add(a, b) => self.arith(a, b, ctx, i64::wrapping_add),
            ConditionExpr::Sub(a, b) => self.arith(a, b, ctx, i64::wrapping_sub),
            ConditionExpr::Mul(a, b) => self.arith(a, b, ctx, i64::wrapping_mul),
            ConditionExpr::Div(a, b) => {
                let bv = try_opt!(self.eval(b, ctx).as_int());
                if bv == 0 { return EvalResult::Undefined; }
                self.arith(a, b, ctx, i64::wrapping_div)
            }
            ConditionExpr::Mod(a, b) => {
                let bv = try_opt!(self.eval(b, ctx).as_int());
                if bv == 0 { return EvalResult::Undefined; }
                self.arith(a, b, ctx, i64::wrapping_rem)
            }
            ConditionExpr::BitAnd(a, b) => self.arith(a, b, ctx, |x, y| x & y),
            ConditionExpr::BitOr(a, b)  => self.arith(a, b, ctx, |x, y| x | y),
            ConditionExpr::BitXor(a, b) => self.arith(a, b, ctx, |x, y| x ^ y),
            ConditionExpr::BitNot(a) => EvalResult::int(!try_opt!(self.eval(a, ctx).as_int())),
            ConditionExpr::Shl(a, b) => self.arith(a, b, ctx, |x, y| x.wrapping_shl(u32::try_from(y & 63).unwrap_or(0))),
            ConditionExpr::Shr(a, b) => self.arith(a, b, ctx, |x, y| x.wrapping_shr(u32::try_from(y & 63).unwrap_or(0))),
            ConditionExpr::Neg(a) => EvalResult::int(-try_opt!(self.eval(a, ctx).as_int())),
            ConditionExpr::Eq(a, b)  => self.cmp(a, b, ctx, |x, y| x == y),
            ConditionExpr::Ne(a, b)  => self.cmp(a, b, ctx, |x, y| x != y),
            ConditionExpr::Lt(a, b)  => self.cmp(a, b, ctx, |x, y| x < y),
            ConditionExpr::Le(a, b)  => self.cmp(a, b, ctx, |x, y| x <= y),
            ConditionExpr::Gt(a, b)  => self.cmp(a, b, ctx, |x, y| x > y),
            ConditionExpr::Ge(a, b)  => self.cmp(a, b, ctx, |x, y| x >= y),
            ConditionExpr::Contains(a, b)   => { let (s, p) = try_opt!(self.eval_str_pair(a, b, ctx)); EvalResult::bool(s.contains(p.as_str())) }
            ConditionExpr::IContains(a, b)  => { let (s, p) = try_opt!(self.eval_str_pair(a, b, ctx)); EvalResult::bool(s.to_lowercase().contains(&p.to_lowercase())) }
            ConditionExpr::StartsWith(a, b) => { let (s, p) = try_opt!(self.eval_str_pair(a, b, ctx)); EvalResult::bool(s.starts_with(p.as_str())) }
            ConditionExpr::EndsWith(a, b)   => { let (s, p) = try_opt!(self.eval_str_pair(a, b, ctx)); EvalResult::bool(s.ends_with(p.as_str())) }
            ConditionExpr::Matches(a, _regex) => {
                let EvalResult::Str(_s) = self.eval(a, ctx) else { return EvalResult::Undefined; };
                EvalResult::Bool(false)
            }
            ConditionExpr::And(a, b) => {
                if !self.eval(a, ctx).as_bool().unwrap_or(false) { return EvalResult::Bool(false); }
                EvalResult::bool(self.eval(b, ctx).as_bool().unwrap_or(false))
            }
            ConditionExpr::Or(a, b) => {
                if self.eval(a, ctx).as_bool().unwrap_or(false) { return EvalResult::Bool(true); }
                EvalResult::bool(self.eval(b, ctx).as_bool().unwrap_or(false))
            }
            ConditionExpr::Not(a) => EvalResult::bool(!self.eval(a, ctx).as_bool().unwrap_or(false)),
            ConditionExpr::ForOf { quantifier, ids, body } => self.eval_for_of(quantifier, ids, body, ctx),
            ConditionExpr::ModuleField { module, field } => {
                ctx.module_data.get(module).and_then(|m| m.get(field))
                    .map_or(EvalResult::Undefined, |v| match v {
                        ModuleValue::Int(i)   => EvalResult::Int(*i),
                        ModuleValue::Bool(b)  => EvalResult::Bool(*b),
                        ModuleValue::Str(s)   => EvalResult::Str(s.clone()),
                        ModuleValue::Float(f) => EvalResult::Float(*f),
                        ModuleValue::Bytes(_) => EvalResult::Undefined,
                    })
            }
            ConditionExpr::Var(name) => {
                if let Some(&i) = ctx.int_vars.get(name) { EvalResult::Int(i) }
                else if let Some(&b) = ctx.bool_vars.get(name) { EvalResult::Bool(b) }
                else { EvalResult::Undefined }
            }
            ConditionExpr::IntFunc { func, offset } => {
                let off = match self.eval(offset, ctx).as_int() {
                    Some(i) if i >= 0 => usize::try_from(i).unwrap_or(usize::MAX),
                    _ => return EvalResult::Undefined,
                };
                self.eval_int_func(func, off)
            }
            _ => EvalResult::Undefined,
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn arith(
        &self,
        a: &ConditionExpr,
        b: &ConditionExpr,
        ctx: &EvalContext,
        op: impl Fn(i64, i64) -> i64,
    ) -> EvalResult {
        let av = try_opt!(self.eval(a, ctx).as_int());
        let bv = try_opt!(self.eval(b, ctx).as_int());
        EvalResult::int(op(av, bv))
    }

    fn cmp(
        &self,
        a: &ConditionExpr,
        b: &ConditionExpr,
        ctx: &EvalContext,
        op: impl Fn(i64, i64) -> bool,
    ) -> EvalResult {
        let av = try_opt!(self.eval(a, ctx).as_int());
        let bv = try_opt!(self.eval(b, ctx).as_int());
        EvalResult::bool(op(av, bv))
    }

    fn eval_str_pair(
        &self,
        a: &ConditionExpr,
        b: &ConditionExpr,
        ctx: &EvalContext,
    ) -> Option<(String, String)> {
        let EvalResult::Str(s) = self.eval(a, ctx) else { return None };
        let EvalResult::Str(p) = self.eval(b, ctx) else { return None };
        Some((s, p))
    }

    fn eval_for_of(
        &self,
        quantifier: &Quantifier,
        ids: &[String],
        body: &ConditionExpr,
        ctx: &EvalContext,
    ) -> EvalResult {
        let total = ids.len();
        let mut matched = 0usize;

        for id in ids {
            // Bind the current string id as a loop variable and evaluate body
            let mut inner_ctx = EvalContext {
                string_matches: ctx.string_matches.clone(),
                file_size: ctx.file_size,
                entry_point: ctx.entry_point,
                module_data: ctx.module_data.clone(),
                int_vars: ctx.int_vars.clone(),
                bool_vars: ctx.bool_vars.clone(),
            };
            // For each match offset of `id`, evaluate body with a virtual "$"
            let offsets = ctx.string_matches.get(id).cloned().unwrap_or_default();
            let body_matched = if offsets.is_empty() {
                false
            } else {
                // Evaluate body with the offsets substituted
                inner_ctx.string_matches.insert("$".to_string(), offsets);
                self.eval(body, &inner_ctx).as_bool().unwrap_or(false)
            };
            if body_matched {
                matched += 1;
            }
        }

        let result = match quantifier {
            Quantifier::Any  => matched > 0,
            Quantifier::All  => matched == total,
            Quantifier::None => matched == 0,
            Quantifier::N(n_expr) => {
                let n = self.eval(n_expr, ctx).as_int().unwrap_or(0);
                i64::try_from(matched).unwrap_or(i64::MAX) >= n
            }
        };
        EvalResult::bool(result)
    }

    fn eval_int_func(&self, func: &IntFunc, offset: usize) -> EvalResult {
        let bytes = &self.file_bytes;
        macro_rules! read_le {
            ($n:expr, u64) => {{
                if offset + $n > bytes.len() { return EvalResult::Undefined; }
                let mut buf = [0u8; $n];
                buf.copy_from_slice(&bytes[offset..offset + $n]);
                u64::from_le_bytes(buf).cast_signed()
            }};
            ($n:expr, $ty:ty) => {{
                if offset + $n > bytes.len() { return EvalResult::Undefined; }
                let mut buf = [0u8; $n];
                buf.copy_from_slice(&bytes[offset..offset + $n]);
                i64::from(<$ty>::from_le_bytes(buf))
            }};
        }
        macro_rules! read_be {
            ($n:expr, u64) => {{
                if offset + $n > bytes.len() { return EvalResult::Undefined; }
                let mut buf = [0u8; $n];
                buf.copy_from_slice(&bytes[offset..offset + $n]);
                u64::from_be_bytes(buf).cast_signed()
            }};
            ($n:expr, $ty:ty) => {{
                if offset + $n > bytes.len() { return EvalResult::Undefined; }
                let mut buf = [0u8; $n];
                buf.copy_from_slice(&bytes[offset..offset + $n]);
                i64::from(<$ty>::from_be_bytes(buf))
            }};
        }
        let v = match func {
            IntFunc::Uint8   => read_le!(1, u8),
            IntFunc::Uint16  => read_le!(2, u16),
            IntFunc::Uint32  => read_le!(4, i32),
            IntFunc::Uint64  => read_le!(8, u64),
            IntFunc::Int8    => read_le!(1, i8),
            IntFunc::Int16   => read_le!(2, i16),
            IntFunc::Int32   => read_le!(4, i32),
            IntFunc::Int64   => read_le!(8, i64),
            IntFunc::Uint8Be  => read_be!(1, u8),
            IntFunc::Uint16Be => read_be!(2, u16),
            IntFunc::Uint32Be => read_be!(4, i32),
            IntFunc::Uint64Be => read_be!(8, u64),
        };
        EvalResult::Int(v)
    }
}

// (Try and FromResidual implementations removed to support stable toolchain)

// ---------------------------------------------------------------------------
// Rule evaluation wrapper
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CompiledCondition {
    pub rule_name: String,
    pub condition: ConditionExpr,
}

impl CompiledCondition {
    pub fn new(rule_name: impl Into<String>, condition: ConditionExpr) -> Self {
        Self {
            rule_name: rule_name.into(),
            condition,
        }
    }

    #[must_use] 
    pub fn evaluate(&self, eval: &ConditionEvaluator, ctx: &EvalContext) -> bool {
        eval.eval(&self.condition, ctx)
            .as_bool()
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> EvalContext {
        let mut ctx = EvalContext::new();
        ctx.add_matches("$s1", vec![0, 100, 200]);
        ctx.add_matches("$s2", vec![50]);
        ctx.file_size = 1024;
        ctx.entry_point = 0x1000;
        ctx
    }

    fn eval(expr: ConditionExpr) -> EvalResult {
        let evaluator = ConditionEvaluator::new();
        evaluator.eval(&expr, &make_ctx())
    }

    #[test]
    fn test_literals() {
        assert_eq!(eval(ConditionExpr::True), EvalResult::Bool(true));
        assert_eq!(eval(ConditionExpr::False), EvalResult::Bool(false));
        assert_eq!(eval(ConditionExpr::Int(42)), EvalResult::Int(42));
    }

    #[test]
    fn test_string_match() {
        assert_eq!(eval(ConditionExpr::StringMatch("$s1".to_string())), EvalResult::Bool(true));
        assert_eq!(eval(ConditionExpr::StringMatch("$noexist".to_string())), EvalResult::Bool(false));
    }

    #[test]
    fn test_string_count() {
        assert_eq!(eval(ConditionExpr::StringCount("$s1".to_string())), EvalResult::Int(3));
        assert_eq!(eval(ConditionExpr::StringCount("$noexist".to_string())), EvalResult::Int(0));
    }

    #[test]
    fn test_string_at() {
        let expr = ConditionExpr::StringAt {
            id: "$s1".to_string(),
            offset: Box::new(ConditionExpr::Int(100)),
        };
        assert_eq!(eval(expr), EvalResult::Bool(true));

        let expr2 = ConditionExpr::StringAt {
            id: "$s1".to_string(),
            offset: Box::new(ConditionExpr::Int(99)),
        };
        assert_eq!(eval(expr2), EvalResult::Bool(false));
    }

    #[test]
    fn test_string_in() {
        let expr = ConditionExpr::StringIn {
            id: "$s2".to_string(),
            from: Box::new(ConditionExpr::Int(0)),
            to: Box::new(ConditionExpr::Int(100)),
        };
        assert_eq!(eval(expr), EvalResult::Bool(true));
    }

    #[test]
    fn test_filesize() {
        assert_eq!(eval(ConditionExpr::Filesize), EvalResult::Int(1024));
    }

    #[test]
    fn test_entrypoint() {
        assert_eq!(eval(ConditionExpr::Entrypoint), EvalResult::Int(0x1000));
    }

    #[test]
    fn test_arithmetic() {
        let add = ConditionExpr::Add(
            Box::new(ConditionExpr::Int(10)),
            Box::new(ConditionExpr::Int(32)),
        );
        assert_eq!(eval(add), EvalResult::Int(42));

        let mul = ConditionExpr::Mul(
            Box::new(ConditionExpr::Int(6)),
            Box::new(ConditionExpr::Int(7)),
        );
        assert_eq!(eval(mul), EvalResult::Int(42));
    }

    #[test]
    fn test_comparison() {
        let gt = ConditionExpr::Gt(
            Box::new(ConditionExpr::Filesize),
            Box::new(ConditionExpr::Int(512)),
        );
        assert_eq!(eval(gt), EvalResult::Bool(true));

        let eq = ConditionExpr::Eq(
            Box::new(ConditionExpr::Int(5)),
            Box::new(ConditionExpr::Int(5)),
        );
        assert_eq!(eval(eq), EvalResult::Bool(true));
    }

    #[test]
    fn test_boolean_and_or_not() {
        let and = ConditionExpr::And(
            Box::new(ConditionExpr::True),
            Box::new(ConditionExpr::True),
        );
        assert_eq!(eval(and), EvalResult::Bool(true));

        let or = ConditionExpr::Or(
            Box::new(ConditionExpr::False),
            Box::new(ConditionExpr::True),
        );
        assert_eq!(eval(or), EvalResult::Bool(true));

        let not = ConditionExpr::Not(Box::new(ConditionExpr::False));
        assert_eq!(eval(not), EvalResult::Bool(true));
    }

    #[test]
    fn test_any_of() {
        let expr = ConditionExpr::AnyOf(vec!["$s1".to_string(), "$noexist".to_string()]);
        assert_eq!(eval(expr), EvalResult::Bool(true));
    }

    #[test]
    fn test_all_of() {
        let expr = ConditionExpr::AllOf(vec!["$s1".to_string(), "$noexist".to_string()]);
        assert_eq!(eval(expr), EvalResult::Bool(false));
    }

    #[test]
    fn test_none_of() {
        let expr = ConditionExpr::NoneOf(vec!["$noexist".to_string()]);
        assert_eq!(eval(expr), EvalResult::Bool(true));
    }

    #[test]
    fn test_n_of() {
        let expr = ConditionExpr::NOf {
            n: Box::new(ConditionExpr::Int(1)),
            ids: vec!["$s1".to_string(), "$noexist".to_string()],
        };
        assert_eq!(eval(expr), EvalResult::Bool(true));
    }

    #[test]
    fn test_uint8_read() {
        let mut evaluator = ConditionEvaluator::new().with_file_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let ctx = EvalContext::new();
        let expr = ConditionExpr::IntFunc {
            func: IntFunc::Uint8,
            offset: Box::new(ConditionExpr::Int(0)),
        };
        assert_eq!(evaluator.eval(&expr, &ctx), EvalResult::Int(0xDE));

        let expr2 = ConditionExpr::IntFunc {
            func: IntFunc::Uint32,
            offset: Box::new(ConditionExpr::Int(0)),
        };
        // LE: 0xEFBEADDE
        assert_eq!(evaluator.eval(&expr2, &ctx), EvalResult::Int(i64::from(0xEFBE_ADDE_u32.cast_signed())));
        let _ = &mut evaluator;
    }

    #[test]
    fn test_module_field() {
        let mut ctx = EvalContext::new();
        let mut pe_fields = HashMap::new();
        pe_fields.insert("number_of_sections".to_string(), ModuleValue::Int(5));
        ctx.module_data.insert("pe".to_string(), pe_fields);

        let evaluator = ConditionEvaluator::new();
        let expr = ConditionExpr::Gt(
            Box::new(ConditionExpr::ModuleField {
                module: "pe".to_string(),
                field: "number_of_sections".to_string(),
            }),
            Box::new(ConditionExpr::Int(3)),
        );
        assert_eq!(evaluator.eval(&expr, &ctx), EvalResult::Bool(true));
    }

    #[test]
    fn test_contains_str() {
        let evaluator = ConditionEvaluator::new();
        let ctx = EvalContext::new();
        let expr = ConditionExpr::Contains(
            Box::new(ConditionExpr::Str("hello world".to_string())),
            Box::new(ConditionExpr::Str("world".to_string())),
        );
        assert_eq!(evaluator.eval(&expr, &ctx), EvalResult::Bool(true));
    }

    #[test]
    fn test_compiled_condition() {
        let cc = CompiledCondition::new(
            "test_rule",
            ConditionExpr::And(
                Box::new(ConditionExpr::StringMatch("$s1".to_string())),
                Box::new(ConditionExpr::Gt(
                    Box::new(ConditionExpr::Filesize),
                    Box::new(ConditionExpr::Int(0)),
                )),
            ),
        );
        let eval = ConditionEvaluator::new();
        assert!(cc.evaluate(&eval, &make_ctx()));
    }
}
