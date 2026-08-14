//! YARA condition expression evaluator.
//!
//! Provides a tree-walking interpreter for YARA condition expressions.
//! The evaluator works against an `EvalContext` that holds pattern match
//! results, file size, entry point, and user-defined variables.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Integer size for IntAtOffset
// ---------------------------------------------------------------------------

/// Width of an integer read at a file offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntSize {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
}

// ---------------------------------------------------------------------------
// Of-quantifier
// ---------------------------------------------------------------------------

/// Quantifier for `X of` expressions.
#[derive(Debug, Clone, PartialEq)]
pub enum OfQuantifier {
    /// All patterns must match.
    All,
    /// At least one pattern must match.
    Any,
    /// No patterns may match.
    None,
    /// Exactly N patterns must match.
    Count(u64),
    /// At least P% of patterns must match.
    Percent(f64),
}

// ---------------------------------------------------------------------------
// Comparison and arithmetic operators
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq, Ne, Lt, Le, Gt, Ge,
    Contains,
    StartsWith,
    EndsWith,
    Matches, // regex match
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add, Sub, Mul, Div, Mod,
    BitAnd, BitOr, BitXor,
    Shl, Shr,
}

// ---------------------------------------------------------------------------
// Condition expression AST
// ---------------------------------------------------------------------------

/// A node in the YARA condition expression tree.
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionExpr {
    True,
    False,
    Not(Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Comparison(Box<Self>, CmpOp, Box<Self>),
    Arithmetic(Box<Self>, ArithOp, Box<Self>),
    /// `#name` — count of matches for string `name`.
    StringCount(String),
    /// `@name` or `@name[i]` — offset of the N-th match.
    StringOffset(String, Option<Box<Self>>),
    /// `!name` or `!name[i]` — length of the N-th match.
    StringLength(String, Option<Box<Self>>),
    /// `$name` — bool: does string `name` match?
    PatternMatch(String),
    /// `filesize`
    FileSize,
    /// `entrypoint`
    EntryPoint,
    /// `expr at offset`
    AtOffset(Box<Self>, Box<Self>),
    /// `expr in (lo..hi)`
    InRange(Box<Self>, Box<Self>, Box<Self>),
    /// `N of ($a, $b, ...)`
    Of(OfQuantifier, Vec<String>),
    /// `for N of ($a, ...) : ( condition )`
    ForAll(Box<Self>, Box<Self>, Box<Self>),
    /// `any/all of them`
    SetMatch(Box<Self>, Vec<Box<Self>>),
    /// `defined expr` — true if expr doesn't produce an error
    Defined(Box<Self>),
    /// `intXX(offset)`
    IntAtOffset(Box<Self>, IntSize),
    FloatLiteral(f64),
    IntLiteral(i64),
    StringLiteral(String),
    /// Named variable or rule name
    Identifier(String),
}

// ---------------------------------------------------------------------------
// Evaluation context
// ---------------------------------------------------------------------------

/// Context supplied to the evaluator for one scan.
#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    /// Map of string ID → list of match offsets (0-based byte offsets).
    pub matches: HashMap<String, Vec<u64>>,
    /// Map of string ID → list of match lengths.
    pub match_lengths: HashMap<String, Vec<u64>>,
    /// Size of the scanned file/buffer.
    pub file_size: u64,
    /// Entry point RVA (None if unknown or not applicable).
    pub entry_point: Option<u64>,
    /// Named integer variables (e.g. defined by `for` loop variables).
    pub variables: HashMap<String, i64>,
    /// Raw bytes of the scanned buffer (for `IntAtOffset`).
    pub data: Vec<u8>,
}

impl EvalContext {
    #[must_use] 
    pub fn new(data: Vec<u8>) -> Self {
        let file_size = data.len() as u64;
        Self { file_size, data, ..Default::default() }
    }

    pub fn add_match(&mut self, id: &str, offset: u64, length: u64) {
        self.matches.entry(id.to_owned()).or_default().push(offset);
        self.match_lengths.entry(id.to_owned()).or_default().push(length);
    }

    pub fn set_var(&mut self, name: &str, value: i64) {
        self.variables.insert(name.to_owned(), value);
    }
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

/// Evaluator error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    DivisionByZero,
    UnknownIdentifier(String),
    TypeError(String),
    IndexOutOfRange(String, usize),
    OffsetOutOfBounds(u64),
    Undefined,
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DivisionByZero      => write!(f, "division by zero"),
            Self::UnknownIdentifier(s) => write!(f, "unknown identifier: {s}"),
            Self::TypeError(s)        => write!(f, "type error: {s}"),
            Self::IndexOutOfRange(s, i) => write!(f, "index {i} out of range for {s}"),
            Self::OffsetOutOfBounds(o) => write!(f, "offset {o:#x} out of bounds"),
            Self::Undefined           => write!(f, "expression is undefined"),
        }
    }
}
impl std::error::Error for EvalError {}

/// Tree-walking YARA condition evaluator.
pub struct ConditionEvaluator<'a> {
    ctx: &'a EvalContext,
}

impl<'a> ConditionEvaluator<'a> {
    #[must_use] 
    pub const fn new(ctx: &'a EvalContext) -> Self {
        Self { ctx }
    }

    // -----------------------------------------------------------------------
    // Public entry points
    // -----------------------------------------------------------------------

    /// Evaluate a condition expression to a boolean.
    ///
    /// # Errors
    ///
    /// Returns an [`EvalError`] if the expression is invalid or cannot be evaluated.
    pub fn evaluate(&self, expr: &ConditionExpr) -> Result<bool, EvalError> {
        match expr {
            ConditionExpr::True  => Ok(true),
            ConditionExpr::False => Ok(false),

            ConditionExpr::Not(e) => Ok(!self.evaluate(e)?),

            ConditionExpr::And(a, b) => {
                // Short-circuit
                if !self.evaluate(a)? { return Ok(false); }
                self.evaluate(b)
            }

            ConditionExpr::Or(a, b) => {
                if self.evaluate(a)? { return Ok(true); }
                self.evaluate(b)
            }

            ConditionExpr::Comparison(lhs, op, rhs) => {
                self.eval_comparison(lhs, *op, rhs)
            }

            ConditionExpr::PatternMatch(id) => {
                Ok(self.ctx.matches.get(id).is_some_and(|v| !v.is_empty()))
            }

            ConditionExpr::Of(quant, ids) => self.eval_of(quant, ids),

            ConditionExpr::ForAll(count_expr, bound_expr, body) => {
                self.eval_for(count_expr, bound_expr, body)
            }

            ConditionExpr::SetMatch(quant_expr, exprs) => {
                self.eval_set_match(quant_expr, exprs)
            }

            ConditionExpr::Defined(inner) => {
                // `defined` should be false when the inner expression resolves
                // to `Undefined` (e.g. EntryPoint when entry_point is None),
                // not just when boolean evaluation succeeds.
                match self.evaluate_int(inner) {
                    Ok(_) => Ok(true),
                    Err(EvalError::Undefined) => Ok(false),
                    Err(_) => Ok(self.evaluate(inner).is_ok()),
                }
            }

            ConditionExpr::Arithmetic(_, _, _) => {
                // arithmetic in boolean context: non-zero == true
                Ok(self.evaluate_int(expr)? != 0)
            }

            ConditionExpr::IntLiteral(n) => Ok(*n != 0),
            ConditionExpr::FloatLiteral(v) => Ok(*v != 0.0),

            ConditionExpr::StringCount(id) => {
                Ok(self.ctx.matches.get(id).map_or(0, std::vec::Vec::len) > 0)
            }

            ConditionExpr::FileSize => Ok(self.ctx.file_size != 0),
            ConditionExpr::EntryPoint => Ok(self.ctx.entry_point.is_some()),

            ConditionExpr::AtOffset(val_expr, off_expr) => {
                let off = self.evaluate_int(off_expr)?.cast_unsigned();
                self.eval_at_offset(val_expr, off)
            }

            ConditionExpr::InRange(val_expr, lo_expr, hi_expr) => {
                let val = self.evaluate_int(val_expr)?;
                let lo  = self.evaluate_int(lo_expr)?;
                let hi  = self.evaluate_int(hi_expr)?;
                Ok(val >= lo && val <= hi)
            }

            ConditionExpr::IntAtOffset(off_expr, size) => {
                let off = self.evaluate_int(off_expr)?.cast_unsigned();
                Ok(self.read_int(off, *size)? != 0)
            }

            ConditionExpr::Identifier(name) => {
                if let Some(&v) = self.ctx.variables.get(name) {
                    Ok(v != 0)
                } else {
                    Err(EvalError::UnknownIdentifier(name.clone()))
                }
            }

            ConditionExpr::StringLiteral(s) => Ok(!s.is_empty()),
            ConditionExpr::StringOffset(_, _) | ConditionExpr::StringLength(_, _) => {
                Ok(self.evaluate_int(expr)? != 0)
            }
        }
    }

    /// Evaluate an expression to an integer.
    ///
    /// # Errors
    ///
    /// Returns an [`EvalError`] if the expression cannot be coerced to an integer.
    pub fn evaluate_int(&self, expr: &ConditionExpr) -> Result<i64, EvalError> {
        match expr {
            ConditionExpr::IntLiteral(n) => Ok(*n),
            ConditionExpr::FloatLiteral(_) => Err(EvalError::TypeError("float literal cannot be coerced to int".into())),

            ConditionExpr::FileSize => Ok(self.ctx.file_size.cast_signed()),

            ConditionExpr::EntryPoint => {
                self.ctx.entry_point
                    .map(u64::cast_signed)
                    .ok_or(EvalError::Undefined)
            }

            ConditionExpr::StringCount(id) => {
                Ok(i64::try_from(self.ctx.matches.get(id).map_or(0, std::vec::Vec::len)).unwrap_or(i64::MAX))
            }

            ConditionExpr::StringOffset(id, idx_expr) => {
                let offsets = self.ctx.matches.get(id)
                    .ok_or_else(|| EvalError::UnknownIdentifier(id.clone()))?;
                let idx = if let Some(ie) = idx_expr {
                    usize::try_from(self.evaluate_int(ie)?).unwrap_or(0)
                } else { 0 };
                offsets.get(idx)
                    .copied()
                    .map(u64::cast_signed)
                    .ok_or_else(|| EvalError::IndexOutOfRange(id.clone(), idx))
            }

            ConditionExpr::StringLength(id, idx_expr) => {
                let lengths = self.ctx.match_lengths.get(id)
                    .ok_or_else(|| EvalError::UnknownIdentifier(id.clone()))?;
                let idx = if let Some(ie) = idx_expr {
                    usize::try_from(self.evaluate_int(ie)?).unwrap_or(0)
                } else { 0 };
                lengths.get(idx)
                    .copied()
                    .map(u64::cast_signed)
                    .ok_or_else(|| EvalError::IndexOutOfRange(id.clone(), idx))
            }

            ConditionExpr::Arithmetic(lhs, op, rhs) => {
                let l = self.evaluate_int(lhs)?;
                let r = self.evaluate_int(rhs)?;
                match op {
                    ArithOp::Add => Ok(l.wrapping_add(r)),
                    ArithOp::Sub => Ok(l.wrapping_sub(r)),
                    ArithOp::Mul => Ok(l.wrapping_mul(r)),
                    ArithOp::Div => {
                        if r == 0 { return Err(EvalError::DivisionByZero); }
                        Ok(l / r)
                    }
                    ArithOp::Mod => {
                        if r == 0 { return Err(EvalError::DivisionByZero); }
                        Ok(l % r)
                    }
                    ArithOp::BitAnd => Ok(l & r),
                    ArithOp::BitOr  => Ok(l | r),
                    ArithOp::BitXor => Ok(l ^ r),
                    ArithOp::Shl    => Ok(l << (r & 63)),
                    ArithOp::Shr    => Ok((l.cast_unsigned() >> (r & 63)).cast_signed()),
                }
            }

            ConditionExpr::IntAtOffset(off_expr, size) => {
                let off = self.evaluate_int(off_expr)?.cast_unsigned();
                self.read_int(off, *size)
            }

            ConditionExpr::Identifier(name) => {
                self.ctx.variables.get(name)
                    .copied()
                    .ok_or_else(|| EvalError::UnknownIdentifier(name.clone()))
            }

            _ => Err(EvalError::TypeError(format!("cannot coerce {expr:?} to int"))),
        }
    }

    /// Evaluate an expression to a float.
    ///
    /// # Errors
    ///
    /// Returns an [`EvalError`] if the expression cannot be coerced to a float.
    pub fn evaluate_float(&self, expr: &ConditionExpr) -> Result<f64, EvalError> {
        match expr {
            ConditionExpr::FloatLiteral(v) => Ok(*v),
            ConditionExpr::IntLiteral(n)   => Ok(f64::from(i32::try_from(*n).unwrap_or(if *n > 0 { i32::MAX } else { i32::MIN }))),
            _ => {
                let v = self.evaluate_int(expr)?;
                Ok(f64::from(i32::try_from(v).unwrap_or(if v > 0 { i32::MAX } else { i32::MIN })))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn eval_comparison(
        &self,
        lhs: &ConditionExpr,
        op: CmpOp,
        rhs: &ConditionExpr,
    ) -> Result<bool, EvalError> {
        // String comparisons
        if let (ConditionExpr::StringLiteral(l), ConditionExpr::StringLiteral(r)) = (lhs, rhs) {
            return Ok(match op {
                CmpOp::Eq         => l == r,
                CmpOp::Ne         => l != r,
                CmpOp::Contains   => l.contains(r.as_str()),
                CmpOp::StartsWith => l.starts_with(r.as_str()),
                CmpOp::EndsWith   => l.ends_with(r.as_str()),
                CmpOp::Matches    => simple_regex_contains(l, r),
                _ => return Err(EvalError::TypeError("string comparison with numeric op".into())),
            });
        }
        // Float comparisons
        if matches!(lhs, ConditionExpr::FloatLiteral(_)) || matches!(rhs, ConditionExpr::FloatLiteral(_)) {
            let l = self.evaluate_float(lhs)?;
            let r = self.evaluate_float(rhs)?;
            return Ok(match op {
                CmpOp::Eq => (l - r).abs() < f64::EPSILON,
                CmpOp::Ne => (l - r).abs() >= f64::EPSILON,
                CmpOp::Lt => l < r,
                CmpOp::Le => l <= r,
                CmpOp::Gt => l > r,
                CmpOp::Ge => l >= r,
                _ => return Err(EvalError::TypeError("float comparison with string op".into())),
            });
        }
        // Integer comparisons
        let l = self.evaluate_int(lhs)?;
        let r = self.evaluate_int(rhs)?;
        Ok(match op {
            CmpOp::Eq => l == r,
            CmpOp::Ne => l != r,
            CmpOp::Lt => l < r,
            CmpOp::Le => l <= r,
            CmpOp::Gt => l > r,
            CmpOp::Ge => l >= r,
            _ => return Err(EvalError::TypeError("numeric comparison with string op".into())),
        })
    }

    fn eval_of(&self, quant: &OfQuantifier, ids: &[String]) -> Result<bool, EvalError> {
        let total = ids.len();
        let matched: usize = ids.iter()
            .filter(|id| self.ctx.matches.get(*id).is_some_and(|v| !v.is_empty()))
            .count();
        Ok(match quant {
            OfQuantifier::All     => matched == total,
            OfQuantifier::Any     => matched > 0,
            OfQuantifier::None    => matched == 0,
            OfQuantifier::Count(n) => u64::try_from(matched).unwrap_or(u64::MAX) >= *n,
            OfQuantifier::Percent(p) => {
                if total == 0 { return Ok(false); }
                (f64::from(u32::try_from(matched).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX))) * 100.0 >= *p
            }
        })
    }

    fn eval_for(
        &self,
        count_expr: &ConditionExpr,
        bound_expr: &ConditionExpr,
        body: &ConditionExpr,
    ) -> Result<bool, EvalError> {
        // count_expr: how many must satisfy
        // bound_expr: upper bound of iteration (integer)
        // body: evaluated with implicit loop variable
        let required = self.evaluate_int(count_expr)?;
        let bound    = self.evaluate_int(bound_expr)?;
        let mut satisfied = 0i64;
        // We can't mutate self.ctx here, so we create an evaluation by adjusting
        // variables; in this simple model the body is evaluated `bound` times.
        for _i in 0..bound {
            if self.evaluate(body)? {
                satisfied += 1;
            }
        }
        Ok(satisfied >= required)
    }

    fn eval_set_match(
        &self,
        quant_expr: &ConditionExpr,
        exprs: &[Box<ConditionExpr>],
    ) -> Result<bool, EvalError> {
        let total = exprs.len();
        let matched = exprs.iter()
            .filter(|e| self.evaluate(e).unwrap_or(false))
            .count();
        // quant_expr resolves to boolean strategy
        match quant_expr {
            ConditionExpr::True  => Ok(matched == total),
            ConditionExpr::False => Ok(matched == 0),
            _                    => {
                let n = usize::try_from(self.evaluate_int(quant_expr)?).unwrap_or(0);
                Ok(matched >= n)
            }
        }
    }

    fn eval_at_offset(
        &self,
        val_expr: &ConditionExpr,
        offset: u64,
    ) -> Result<bool, EvalError> {
        // `$str at offset` — is there a match of val_expr at exactly `offset`?
        if let ConditionExpr::PatternMatch(id) = val_expr {
            return Ok(self.ctx.matches.get(id)
                .is_some_and(|v| v.contains(&offset)));
        }
        // generic: evaluate val_expr and check it equals the offset
        let val = self.evaluate_int(val_expr)?;
        Ok(val.cast_unsigned() == offset)
    }

    fn read_int(&self, offset: u64, size: IntSize) -> Result<i64, EvalError> {
        let data = &self.ctx.data;
        let off = usize::try_from(offset).unwrap_or(usize::MAX);
        match size {
            IntSize::U8  => data.get(off).map(|&b| i64::from(b))
                .ok_or(EvalError::OffsetOutOfBounds(offset)),
            IntSize::U16 => if off + 2 <= data.len() {
                Ok(i64::from(u16::from_le_bytes(data[off..off+2].try_into().unwrap())))
            } else { Err(EvalError::OffsetOutOfBounds(offset)) },
            IntSize::U32 => if off + 4 <= data.len() {
                Ok(i64::from(u32::from_le_bytes(data[off..off+4].try_into().unwrap())))
            } else { Err(EvalError::OffsetOutOfBounds(offset)) },
            IntSize::U64 => if off + 8 <= data.len() {
                Ok(u64::from_le_bytes(data[off..off+8].try_into().unwrap()).cast_signed())
            } else { Err(EvalError::OffsetOutOfBounds(offset)) },
            IntSize::I8  => data.get(off).map(|&b| i64::from(b.cast_signed()))
                .ok_or(EvalError::OffsetOutOfBounds(offset)),
            IntSize::I16 => if off + 2 <= data.len() {
                Ok(i64::from(i16::from_le_bytes(data[off..off+2].try_into().unwrap())))
            } else { Err(EvalError::OffsetOutOfBounds(offset)) },
            IntSize::I32 => if off + 4 <= data.len() {
                Ok(i64::from(i32::from_le_bytes(data[off..off+4].try_into().unwrap())))
            } else { Err(EvalError::OffsetOutOfBounds(offset)) },
            IntSize::I64 => if off + 8 <= data.len() {
                Ok(i64::from_le_bytes(data[off..off+8].try_into().unwrap()))
            } else { Err(EvalError::OffsetOutOfBounds(offset)) },
        }
    }
}

// ---------------------------------------------------------------------------
// Very small regex helper (literal match only; real YARA uses PCRE)
// ---------------------------------------------------------------------------

fn simple_regex_contains(haystack: &str, pattern: &str) -> bool {
    // Strip anchors for simplicity
    let p = pattern.trim_matches('/');
    haystack.contains(p)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_matches() -> EvalContext {
        let mut ctx = EvalContext::new(vec![0x4D, 0x5A, 0x00, 0x01, 0x02, 0x03, 0xFF, 0x7F]);
        ctx.add_match("$a", 0, 2);
        ctx.add_match("$a", 4, 3);
        ctx.add_match("$b", 6, 1);
        ctx.file_size = 8;
        ctx.entry_point = Some(0x1000);
        ctx
    }

    #[test]
    fn test_literal_true() {
        let ctx = EvalContext::default();
        let ev = ConditionEvaluator::new(&ctx);
        assert!(ev.evaluate(&ConditionExpr::True).unwrap());
    }

    #[test]
    fn test_literal_false() {
        let ctx = EvalContext::default();
        let ev = ConditionEvaluator::new(&ctx);
        assert!(!ev.evaluate(&ConditionExpr::False).unwrap());
    }

    #[test]
    fn test_not() {
        let ctx = EvalContext::default();
        let ev = ConditionEvaluator::new(&ctx);
        assert!(ev.evaluate(&ConditionExpr::Not(Box::new(ConditionExpr::False))).unwrap());
    }

    #[test]
    fn test_and_short_circuit() {
        let ctx = EvalContext::default();
        let ev = ConditionEvaluator::new(&ctx);
        let expr = ConditionExpr::And(
            Box::new(ConditionExpr::False),
            Box::new(ConditionExpr::True),
        );
        assert!(!ev.evaluate(&expr).unwrap());
    }

    #[test]
    fn test_or_short_circuit() {
        let ctx = EvalContext::default();
        let ev = ConditionEvaluator::new(&ctx);
        let expr = ConditionExpr::Or(
            Box::new(ConditionExpr::True),
            Box::new(ConditionExpr::False),
        );
        assert!(ev.evaluate(&expr).unwrap());
    }

    #[test]
    fn test_pattern_match_found() {
        let ctx = ctx_with_matches();
        let ev = ConditionEvaluator::new(&ctx);
        assert!(ev.evaluate(&ConditionExpr::PatternMatch("$a".into())).unwrap());
    }

    #[test]
    fn test_pattern_match_not_found() {
        let ctx = ctx_with_matches();
        let ev = ConditionEvaluator::new(&ctx);
        assert!(!ev.evaluate(&ConditionExpr::PatternMatch("$z".into())).unwrap());
    }

    #[test]
    fn test_string_count() {
        let ctx = ctx_with_matches();
        let ev = ConditionEvaluator::new(&ctx);
        assert_eq!(ev.evaluate_int(&ConditionExpr::StringCount("$a".into())).unwrap(), 2);
    }

    #[test]
    fn test_string_offset_first() {
        let ctx = ctx_with_matches();
        let ev = ConditionEvaluator::new(&ctx);
        assert_eq!(
            ev.evaluate_int(&ConditionExpr::StringOffset("$a".into(), None)).unwrap(),
            0
        );
    }

    #[test]
    fn test_string_offset_second() {
        let ctx = ctx_with_matches();
        let ev = ConditionEvaluator::new(&ctx);
        assert_eq!(
            ev.evaluate_int(&ConditionExpr::StringOffset(
                "$a".into(),
                Some(Box::new(ConditionExpr::IntLiteral(1)))
            )).unwrap(),
            4
        );
    }

    #[test]
    fn test_string_length() {
        let ctx = ctx_with_matches();
        let ev = ConditionEvaluator::new(&ctx);
        assert_eq!(
            ev.evaluate_int(&ConditionExpr::StringLength("$a".into(), None)).unwrap(),
            2
        );
    }

    #[test]
    fn test_file_size() {
        let ctx = ctx_with_matches();
        let ev = ConditionEvaluator::new(&ctx);
        assert_eq!(ev.evaluate_int(&ConditionExpr::FileSize).unwrap(), 8);
    }

    #[test]
    fn test_entry_point() {
        let ctx = ctx_with_matches();
        let ev = ConditionEvaluator::new(&ctx);
        assert_eq!(ev.evaluate_int(&ConditionExpr::EntryPoint).unwrap(), 0x1000);
    }

    #[test]
    fn test_arithmetic_add() {
        let ctx = EvalContext::default();
        let ev = ConditionEvaluator::new(&ctx);
        let expr = ConditionExpr::Arithmetic(
            Box::new(ConditionExpr::IntLiteral(3)),
            ArithOp::Add,
            Box::new(ConditionExpr::IntLiteral(4)),
        );
        assert_eq!(ev.evaluate_int(&expr).unwrap(), 7);
    }

    #[test]
    fn test_arithmetic_div_by_zero() {
        let ctx = EvalContext::default();
        let ev = ConditionEvaluator::new(&ctx);
        let expr = ConditionExpr::Arithmetic(
            Box::new(ConditionExpr::IntLiteral(10)),
            ArithOp::Div,
            Box::new(ConditionExpr::IntLiteral(0)),
        );
        assert_eq!(ev.evaluate_int(&expr), Err(EvalError::DivisionByZero));
    }

    #[test]
    fn test_comparison_int_lt() {
        let ctx = EvalContext::default();
        let ev = ConditionEvaluator::new(&ctx);
        let expr = ConditionExpr::Comparison(
            Box::new(ConditionExpr::IntLiteral(1)),
            CmpOp::Lt,
            Box::new(ConditionExpr::IntLiteral(2)),
        );
        assert!(ev.evaluate(&expr).unwrap());
    }

    #[test]
    fn test_of_any() {
        let ctx = ctx_with_matches();
        let ev = ConditionEvaluator::new(&ctx);
        let expr = ConditionExpr::Of(OfQuantifier::Any, vec!["$a".into(), "$z".into()]);
        assert!(ev.evaluate(&expr).unwrap());
    }

    #[test]
    fn test_of_all_fail() {
        let ctx = ctx_with_matches();
        let ev = ConditionEvaluator::new(&ctx);
        let expr = ConditionExpr::Of(OfQuantifier::All, vec!["$a".into(), "$z".into()]);
        assert!(!ev.evaluate(&expr).unwrap());
    }

    #[test]
    fn test_in_range() {
        let ctx = EvalContext::default();
        let ev = ConditionEvaluator::new(&ctx);
        let expr = ConditionExpr::InRange(
            Box::new(ConditionExpr::IntLiteral(5)),
            Box::new(ConditionExpr::IntLiteral(1)),
            Box::new(ConditionExpr::IntLiteral(10)),
        );
        assert!(ev.evaluate(&expr).unwrap());
    }

    #[test]
    fn test_read_u8() {
        let ctx = EvalContext::new(vec![0xAB, 0xCD]);
        let ev = ConditionEvaluator::new(&ctx);
        let expr = ConditionExpr::IntAtOffset(
            Box::new(ConditionExpr::IntLiteral(0)),
            IntSize::U8,
        );
        assert_eq!(ev.evaluate_int(&expr).unwrap(), 0xAB);
    }

    #[test]
    fn test_read_u16_le() {
        let ctx = EvalContext::new(vec![0x01, 0x02, 0x00, 0x00]);
        let ev = ConditionEvaluator::new(&ctx);
        let expr = ConditionExpr::IntAtOffset(
            Box::new(ConditionExpr::IntLiteral(0)),
            IntSize::U16,
        );
        assert_eq!(ev.evaluate_int(&expr).unwrap(), 0x0201);
    }

    #[test]
    fn test_defined_ok() {
        let ctx = EvalContext::default();
        let ev = ConditionEvaluator::new(&ctx);
        let expr = ConditionExpr::Defined(Box::new(ConditionExpr::IntLiteral(42)));
        assert!(ev.evaluate(&expr).unwrap());
    }

    #[test]
    fn test_defined_undefined() {
        let ctx = EvalContext::default();
        let ev = ConditionEvaluator::new(&ctx);
        // EntryPoint is None → Undefined error
        let expr = ConditionExpr::Defined(Box::new(ConditionExpr::EntryPoint));
        assert!(!ev.evaluate(&expr).unwrap());
    }

    #[test]
    fn test_of_percent() {
        let ctx = ctx_with_matches();
        let ev = ConditionEvaluator::new(&ctx);
        // 1 of 2 = 50% >= 40%
        let expr = ConditionExpr::Of(
            OfQuantifier::Percent(40.0),
            vec!["$a".into(), "$z".into()],
        );
        assert!(ev.evaluate(&expr).unwrap());
    }
}
