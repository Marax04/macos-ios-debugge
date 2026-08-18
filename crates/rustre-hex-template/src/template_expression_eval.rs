//! `template_expression_eval` — Expression evaluator for hex templates.
//!
//! Provides a complete expression language for binary template fields:
//! arithmetic, bitwise, comparison, logical, and ternary operators, function
//! calls (min, max, align, sizeof, …), and field-reference lookups.  The
//! evaluator operates on a context of previously-parsed field values and
//! produces an [`EvalResult`].

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by expression evaluation.
#[derive(Debug, Error, Clone)]
pub enum EvalError {
    /// A named field was not found in the evaluation context.
    #[error("field '{0}' not found")]
    FieldNotFound(String),
    /// Attempted division by zero.
    #[error("division by zero in expression")]
    DivisionByZero,
    /// Shift amount out of range.
    #[error("shift amount {0} is out of range (0..64)")]
    ShiftOutOfRange(u64),
    /// Arithmetic overflow in a checked operation.
    #[error("arithmetic overflow")]
    Overflow,
    /// Calling an unknown built-in function.
    #[error("unknown function '{0}'")]
    UnknownFunction(String),
    /// Wrong number of arguments to a built-in function.
    #[error("function '{name}' expects {expected} args, got {got}")]
    WrongArgCount {
        name: String,
        expected: usize,
        got: usize,
    },
    /// A type name referenced in `sizeof()` is not registered.
    #[error("sizeof: type '{0}' not registered")]
    TypeNotFound(String),
    /// Expression evaluation exceeded the recursion limit.
    #[error("expression recursion depth exceeded")]
    RecursionLimit,
    /// A string operation was attempted on a non-string value.
    #[error("type mismatch: expected {expected}, got {got}")]
    TypeMismatch { expected: String, got: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// EvalResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of evaluating a template expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EvalResult {
    /// Unsigned 64-bit integer.
    UInt(u64),
    /// Signed 64-bit integer.
    SInt(i64),
    /// Boolean (produced by comparison / logical ops).
    Bool(bool),
    /// 64-bit float.
    Float(f64),
    /// String value (from string field references or string literals).
    Str(String),
    /// Byte array.
    Bytes(Vec<u8>),
}

impl EvalResult {
    /// Coerce to `u64` if possible.
    ///
    /// # Errors
    ///
    /// Returns [`EvalError::TypeMismatch`] if the value is not numeric.
    pub fn to_u64(&self) -> Result<u64, EvalError> {
        match self {
            Self::UInt(v) => Ok(*v),
            Self::SInt(v) => Ok(*v as u64),
            Self::Bool(b) => Ok(u64::from(*b)),
            Self::Float(f) => Ok(*f as u64),
            _ => Err(EvalError::TypeMismatch {
                expected: "integer".to_string(),
                got: self.type_name().to_string(),
            }),
        }
    }

    /// Coerce to `i64` if possible.
    ///
    /// # Errors
    ///
    /// Returns [`EvalError::TypeMismatch`] if the value is not numeric.
    pub fn to_i64(&self) -> Result<i64, EvalError> {
        match self {
            Self::UInt(v) => Ok(*v as i64),
            Self::SInt(v) => Ok(*v),
            Self::Bool(b) => Ok(i64::from(*b)),
            Self::Float(f) => Ok(*f as i64),
            _ => Err(EvalError::TypeMismatch {
                expected: "signed integer".to_string(),
                got: self.type_name().to_string(),
            }),
        }
    }

    /// Coerce to `bool`.
    ///
    /// Integers are truthy when non-zero; strings are truthy when non-empty.
    #[must_use]
    pub fn to_bool(&self) -> bool {
        match self {
            Self::UInt(v) => *v != 0,
            Self::SInt(v) => *v != 0,
            Self::Bool(b) => *b,
            Self::Float(f) => *f != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::Bytes(b) => !b.is_empty(),
        }
    }

    /// Coerce to `f64`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalError::TypeMismatch`] for non-numeric types.
    pub fn to_f64(&self) -> Result<f64, EvalError> {
        match self {
            Self::UInt(v) => Ok(*v as f64),
            Self::SInt(v) => Ok(*v as f64),
            Self::Bool(b) => Ok(f64::from(u8::from(*b))),
            Self::Float(f) => Ok(*f),
            _ => Err(EvalError::TypeMismatch {
                expected: "float".to_string(),
                got: self.type_name().to_string(),
            }),
        }
    }

    /// Return the type name string for error messages.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::UInt(_) => "uint",
            Self::SInt(_) => "sint",
            Self::Bool(_) => "bool",
            Self::Float(_) => "float",
            Self::Str(_) => "str",
            Self::Bytes(_) => "bytes",
        }
    }
}

impl fmt::Display for EvalResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UInt(v) => write!(f, "{v}"),
            Self::SInt(v) => write!(f, "{v}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::Bytes(b) => write!(f, "[{} bytes]", b.len()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateExpr
// ─────────────────────────────────────────────────────────────────────────────

/// An AST node for the template expression language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateExpr {
    // ── Literals ──────────────────────────────────────────────────────────────
    /// Unsigned integer literal.
    LitUInt(u64),
    /// Signed integer literal.
    LitSInt(i64),
    /// Float literal.
    LitFloat(f64),
    /// Boolean literal.
    LitBool(bool),
    /// String literal.
    LitStr(String),

    // ── Field reference ───────────────────────────────────────────────────────
    /// Reference to a previously-parsed field by name.
    Field(String),

    // ── Arithmetic ────────────────────────────────────────────────────────────
    Add(Box<TemplateExpr>, Box<TemplateExpr>),
    Sub(Box<TemplateExpr>, Box<TemplateExpr>),
    Mul(Box<TemplateExpr>, Box<TemplateExpr>),
    Div(Box<TemplateExpr>, Box<TemplateExpr>),
    Mod(Box<TemplateExpr>, Box<TemplateExpr>),
    Neg(Box<TemplateExpr>),

    // ── Bitwise ───────────────────────────────────────────────────────────────
    BitAnd(Box<TemplateExpr>, Box<TemplateExpr>),
    BitOr(Box<TemplateExpr>, Box<TemplateExpr>),
    BitXor(Box<TemplateExpr>, Box<TemplateExpr>),
    BitNot(Box<TemplateExpr>),
    Shl(Box<TemplateExpr>, Box<TemplateExpr>),
    Shr(Box<TemplateExpr>, Box<TemplateExpr>),

    // ── Comparison ────────────────────────────────────────────────────────────
    Eq(Box<TemplateExpr>, Box<TemplateExpr>),
    Ne(Box<TemplateExpr>, Box<TemplateExpr>),
    Lt(Box<TemplateExpr>, Box<TemplateExpr>),
    Le(Box<TemplateExpr>, Box<TemplateExpr>),
    Gt(Box<TemplateExpr>, Box<TemplateExpr>),
    Ge(Box<TemplateExpr>, Box<TemplateExpr>),

    // ── Logical ───────────────────────────────────────────────────────────────
    And(Box<TemplateExpr>, Box<TemplateExpr>),
    Or(Box<TemplateExpr>, Box<TemplateExpr>),
    Not(Box<TemplateExpr>),

    // ── Ternary ───────────────────────────────────────────────────────────────
    /// `condition ? then_expr : else_expr`
    Ternary(
        Box<TemplateExpr>,
        Box<TemplateExpr>,
        Box<TemplateExpr>,
    ),

    // ── Function call ─────────────────────────────────────────────────────────
    /// Built-in or user-registered function call.
    Call {
        name: String,
        args: Vec<TemplateExpr>,
    },
}

impl TemplateExpr {
    /// Convenience: field reference.
    #[must_use]
    pub fn field(name: impl Into<String>) -> Self {
        Self::Field(name.into())
    }

    /// Convenience: `a == b`.
    #[must_use]
    pub fn eq(a: Self, b: Self) -> Self {
        Self::Eq(Box::new(a), Box::new(b))
    }

    /// Convenience: `a != b`.
    #[must_use]
    pub fn ne(a: Self, b: Self) -> Self {
        Self::Ne(Box::new(a), Box::new(b))
    }

    /// Convenience: `a && b`.
    #[must_use]
    pub fn and(a: Self, b: Self) -> Self {
        Self::And(Box::new(a), Box::new(b))
    }

    /// Convenience: `a || b`.
    #[must_use]
    pub fn or(a: Self, b: Self) -> Self {
        Self::Or(Box::new(a), Box::new(b))
    }

    /// Convenience: `!a`.
    #[must_use]
    pub fn not(a: Self) -> Self {
        Self::Not(Box::new(a))
    }

    /// Convenience: `a + b`.
    #[must_use]
    pub fn add(a: Self, b: Self) -> Self {
        Self::Add(Box::new(a), Box::new(b))
    }

    /// Convenience: `a & b`.
    #[must_use]
    pub fn bit_and(a: Self, b: Self) -> Self {
        Self::BitAnd(Box::new(a), Box::new(b))
    }

    /// Convenience: `cond ? t : e`.
    #[must_use]
    pub fn ternary(cond: Self, t: Self, e: Self) -> Self {
        Self::Ternary(Box::new(cond), Box::new(t), Box::new(e))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EvalContext
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluation context: maps field names to their resolved values and provides
/// type size lookups for the `sizeof()` built-in.
#[derive(Debug, Default)]
pub struct EvalContext {
    /// Named field values from previously-parsed template fields.
    fields: HashMap<String, EvalResult>,
    /// Named type sizes for `sizeof(TypeName)`.
    type_sizes: HashMap<String, usize>,
}

impl EvalContext {
    /// Create an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a field value.
    pub fn set(&mut self, name: impl Into<String>, value: EvalResult) {
        self.fields.insert(name.into(), value);
    }

    /// Set a field to a `u64`.
    pub fn set_u64(&mut self, name: impl Into<String>, value: u64) {
        self.set(name, EvalResult::UInt(value));
    }

    /// Look up a field value.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&EvalResult> {
        self.fields.get(name)
    }

    /// Register a type size for `sizeof()`.
    pub fn register_sizeof(&mut self, type_name: impl Into<String>, size: usize) {
        self.type_sizes.insert(type_name.into(), size);
    }

    /// Look up a type size.
    #[must_use]
    pub fn sizeof_type(&self, type_name: &str) -> Option<usize> {
        self.type_sizes.get(type_name).copied()
    }

    /// Number of fields.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateExprEval
// ─────────────────────────────────────────────────────────────────────────────

const MAX_DEPTH: usize = 128;

/// Evaluates [`TemplateExpr`] trees against an [`EvalContext`].
///
/// Thread-safe: immutable after construction.  Create one evaluator per
/// invocation or share across evaluations with the same context.
pub struct TemplateExprEval<'a> {
    ctx: &'a EvalContext,
}

impl<'a> TemplateExprEval<'a> {
    /// Create a new evaluator tied to `ctx`.
    #[must_use]
    pub const fn new(ctx: &'a EvalContext) -> Self {
        Self { ctx }
    }

    /// Evaluate `expr` and return the result.
    ///
    /// # Errors
    ///
    /// Returns [`EvalError`] on type mismatches, division by zero, etc.
    pub fn eval(&self, expr: &TemplateExpr) -> Result<EvalResult, EvalError> {
        self.eval_depth(expr, 0)
    }

    /// Evaluate and coerce to `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalError`] on evaluation or coercion failure.
    pub fn eval_u64(&self, expr: &TemplateExpr) -> Result<u64, EvalError> {
        self.eval(expr)?.to_u64()
    }

    /// Evaluate and coerce to `bool`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalError`] on evaluation failure.
    pub fn eval_bool(&self, expr: &TemplateExpr) -> Result<bool, EvalError> {
        Ok(self.eval(expr)?.to_bool())
    }

    fn eval_depth(&self, expr: &TemplateExpr, depth: usize) -> Result<EvalResult, EvalError> {
        if depth > MAX_DEPTH {
            return Err(EvalError::RecursionLimit);
        }
        let d = depth + 1;
        match expr {
            // ── Literals ──────────────────────────────────────────────────────
            TemplateExpr::LitUInt(v) => Ok(EvalResult::UInt(*v)),
            TemplateExpr::LitSInt(v) => Ok(EvalResult::SInt(*v)),
            TemplateExpr::LitFloat(v) => Ok(EvalResult::Float(*v)),
            TemplateExpr::LitBool(v) => Ok(EvalResult::Bool(*v)),
            TemplateExpr::LitStr(v) => Ok(EvalResult::Str(v.clone())),

            // ── Field reference ───────────────────────────────────────────────
            TemplateExpr::Field(name) => self
                .ctx
                .get(name)
                .cloned()
                .ok_or_else(|| EvalError::FieldNotFound(name.clone())),

            // ── Arithmetic ───────────────────────────────────────────────────
            TemplateExpr::Add(a, b) => {
                let av = self.eval_depth(a, d)?;
                let bv = self.eval_depth(b, d)?;
                self.binop_arith(av, bv, "+")
            }
            TemplateExpr::Sub(a, b) => {
                let av = self.eval_depth(a, d)?;
                let bv = self.eval_depth(b, d)?;
                self.binop_arith(av, bv, "-")
            }
            TemplateExpr::Mul(a, b) => {
                let av = self.eval_depth(a, d)?;
                let bv = self.eval_depth(b, d)?;
                self.binop_arith(av, bv, "*")
            }
            TemplateExpr::Div(a, b) => {
                let av = self.eval_depth(a, d)?;
                let bv = self.eval_depth(b, d)?;
                let bd = bv.to_u64()?;
                if bd == 0 {
                    return Err(EvalError::DivisionByZero);
                }
                Ok(EvalResult::UInt(av.to_u64()? / bd))
            }
            TemplateExpr::Mod(a, b) => {
                let av = self.eval_depth(a, d)?;
                let bv = self.eval_depth(b, d)?;
                let bd = bv.to_u64()?;
                if bd == 0 {
                    return Err(EvalError::DivisionByZero);
                }
                Ok(EvalResult::UInt(av.to_u64()? % bd))
            }
            TemplateExpr::Neg(e) => {
                let v = self.eval_depth(e, d)?;
                Ok(EvalResult::SInt(-v.to_i64()?))
            }

            // ── Bitwise ───────────────────────────────────────────────────────
            TemplateExpr::BitAnd(a, b) => {
                let av = self.eval_depth(a, d)?.to_u64()?;
                let bv = self.eval_depth(b, d)?.to_u64()?;
                Ok(EvalResult::UInt(av & bv))
            }
            TemplateExpr::BitOr(a, b) => {
                let av = self.eval_depth(a, d)?.to_u64()?;
                let bv = self.eval_depth(b, d)?.to_u64()?;
                Ok(EvalResult::UInt(av | bv))
            }
            TemplateExpr::BitXor(a, b) => {
                let av = self.eval_depth(a, d)?.to_u64()?;
                let bv = self.eval_depth(b, d)?.to_u64()?;
                Ok(EvalResult::UInt(av ^ bv))
            }
            TemplateExpr::BitNot(e) => {
                let v = self.eval_depth(e, d)?.to_u64()?;
                Ok(EvalResult::UInt(!v))
            }
            TemplateExpr::Shl(a, b) => {
                let av = self.eval_depth(a, d)?.to_u64()?;
                let bv = self.eval_depth(b, d)?.to_u64()?;
                if bv >= 64 {
                    return Err(EvalError::ShiftOutOfRange(bv));
                }
                Ok(EvalResult::UInt(av << bv))
            }
            TemplateExpr::Shr(a, b) => {
                let av = self.eval_depth(a, d)?.to_u64()?;
                let bv = self.eval_depth(b, d)?.to_u64()?;
                if bv >= 64 {
                    return Err(EvalError::ShiftOutOfRange(bv));
                }
                Ok(EvalResult::UInt(av >> bv))
            }

            // ── Comparison ───────────────────────────────────────────────────
            TemplateExpr::Eq(a, b) => {
                let av = self.eval_depth(a, d)?;
                let bv = self.eval_depth(b, d)?;
                Ok(EvalResult::Bool(self.compare_eq(&av, &bv)))
            }
            TemplateExpr::Ne(a, b) => {
                let av = self.eval_depth(a, d)?;
                let bv = self.eval_depth(b, d)?;
                Ok(EvalResult::Bool(!self.compare_eq(&av, &bv)))
            }
            TemplateExpr::Lt(a, b) => {
                let av = self.eval_depth(a, d)?.to_u64()?;
                let bv = self.eval_depth(b, d)?.to_u64()?;
                Ok(EvalResult::Bool(av < bv))
            }
            TemplateExpr::Le(a, b) => {
                let av = self.eval_depth(a, d)?.to_u64()?;
                let bv = self.eval_depth(b, d)?.to_u64()?;
                Ok(EvalResult::Bool(av <= bv))
            }
            TemplateExpr::Gt(a, b) => {
                let av = self.eval_depth(a, d)?.to_u64()?;
                let bv = self.eval_depth(b, d)?.to_u64()?;
                Ok(EvalResult::Bool(av > bv))
            }
            TemplateExpr::Ge(a, b) => {
                let av = self.eval_depth(a, d)?.to_u64()?;
                let bv = self.eval_depth(b, d)?.to_u64()?;
                Ok(EvalResult::Bool(av >= bv))
            }

            // ── Logical ──────────────────────────────────────────────────────
            TemplateExpr::And(a, b) => {
                // Short-circuit
                let av = self.eval_depth(a, d)?.to_bool();
                if !av {
                    return Ok(EvalResult::Bool(false));
                }
                Ok(EvalResult::Bool(self.eval_depth(b, d)?.to_bool()))
            }
            TemplateExpr::Or(a, b) => {
                // Short-circuit
                let av = self.eval_depth(a, d)?.to_bool();
                if av {
                    return Ok(EvalResult::Bool(true));
                }
                Ok(EvalResult::Bool(self.eval_depth(b, d)?.to_bool()))
            }
            TemplateExpr::Not(e) => {
                let v = self.eval_depth(e, d)?.to_bool();
                Ok(EvalResult::Bool(!v))
            }

            // ── Ternary ──────────────────────────────────────────────────────
            TemplateExpr::Ternary(cond, then_e, else_e) => {
                if self.eval_depth(cond, d)?.to_bool() {
                    self.eval_depth(then_e, d)
                } else {
                    self.eval_depth(else_e, d)
                }
            }

            // ── Function call ─────────────────────────────────────────────────
            TemplateExpr::Call { name, args } => self.call_builtin(name, args, d),
        }
    }

    fn binop_arith(
        &self,
        a: EvalResult,
        b: EvalResult,
        op: &str,
    ) -> Result<EvalResult, EvalError> {
        // Float promotion
        if matches!(a, EvalResult::Float(_)) || matches!(b, EvalResult::Float(_)) {
            let af = a.to_f64()?;
            let bf = b.to_f64()?;
            return Ok(EvalResult::Float(match op {
                "+" => af + bf,
                "-" => af - bf,
                "*" => af * bf,
                _ => af + bf,
            }));
        }
        let au = a.to_u64()?;
        let bu = b.to_u64()?;
        Ok(EvalResult::UInt(match op {
            "+" => au.wrapping_add(bu),
            "-" => au.wrapping_sub(bu),
            "*" => au.wrapping_mul(bu),
            _ => au.wrapping_add(bu),
        }))
    }

    fn compare_eq(&self, a: &EvalResult, b: &EvalResult) -> bool {
        match (a, b) {
            (EvalResult::Str(s1), EvalResult::Str(s2)) => s1 == s2,
            (EvalResult::Bool(b1), EvalResult::Bool(b2)) => b1 == b2,
            _ => a.to_u64().ok() == b.to_u64().ok(),
        }
    }

    fn call_builtin(
        &self,
        name: &str,
        args: &[TemplateExpr],
        depth: usize,
    ) -> Result<EvalResult, EvalError> {
        let eval_arg = |i: usize| -> Result<EvalResult, EvalError> {
            self.eval_depth(&args[i], depth)
        };
        let need = |n: usize| -> Result<(), EvalError> {
            if args.len() != n {
                Err(EvalError::WrongArgCount {
                    name: name.to_string(),
                    expected: n,
                    got: args.len(),
                })
            } else {
                Ok(())
            }
        };
        match name {
            "min" => {
                need(2)?;
                let a = eval_arg(0)?.to_u64()?;
                let b = eval_arg(1)?.to_u64()?;
                Ok(EvalResult::UInt(a.min(b)))
            }
            "max" => {
                need(2)?;
                let a = eval_arg(0)?.to_u64()?;
                let b = eval_arg(1)?.to_u64()?;
                Ok(EvalResult::UInt(a.max(b)))
            }
            "abs" => {
                need(1)?;
                let v = eval_arg(0)?.to_i64()?;
                Ok(EvalResult::SInt(v.abs()))
            }
            "align" => {
                // align(value, alignment) → next multiple of alignment >= value
                need(2)?;
                let val = eval_arg(0)?.to_u64()?;
                let align = eval_arg(1)?.to_u64()?;
                if align == 0 {
                    return Ok(EvalResult::UInt(val));
                }
                let aligned = val
                    .checked_add(align - 1)
                    .ok_or(EvalError::Overflow)?
                    & !(align - 1);
                Ok(EvalResult::UInt(aligned))
            }
            "pad" => {
                // pad(offset, alignment) → padding bytes needed
                need(2)?;
                let val = eval_arg(0)?.to_u64()?;
                let align = eval_arg(1)?.to_u64()?;
                if align == 0 {
                    return Ok(EvalResult::UInt(0));
                }
                let rem = val % align;
                Ok(EvalResult::UInt(if rem == 0 { 0 } else { align - rem }))
            }
            "clamp" => {
                // clamp(value, min, max)
                need(3)?;
                let val = eval_arg(0)?.to_u64()?;
                let lo = eval_arg(1)?.to_u64()?;
                let hi = eval_arg(2)?.to_u64()?;
                Ok(EvalResult::UInt(val.max(lo).min(hi)))
            }
            "bit" => {
                // bit(value, bit_index) → (value >> bit_index) & 1
                need(2)?;
                let val = eval_arg(0)?.to_u64()?;
                let bit = eval_arg(1)?.to_u64()?;
                if bit >= 64 {
                    return Err(EvalError::ShiftOutOfRange(bit));
                }
                Ok(EvalResult::UInt((val >> bit) & 1))
            }
            "bits" => {
                // bits(value, start, count) → extracted bit field
                need(3)?;
                let val = eval_arg(0)?.to_u64()?;
                let start = eval_arg(1)?.to_u64()?;
                let count = eval_arg(2)?.to_u64()?;
                if start >= 64 || count == 0 || start + count > 64 {
                    return Err(EvalError::ShiftOutOfRange(start));
                }
                let mask = if count >= 64 {
                    u64::MAX
                } else {
                    (1u64 << count) - 1
                };
                Ok(EvalResult::UInt((val >> start) & mask))
            }
            "sizeof" => {
                // sizeof("TypeName")
                need(1)?;
                let name_val = eval_arg(0)?;
                let type_name = match &name_val {
                    EvalResult::Str(s) => s.clone(),
                    _ => {
                        return Err(EvalError::TypeMismatch {
                            expected: "string type name".to_string(),
                            got: name_val.type_name().to_string(),
                        })
                    }
                };
                let sz = self
                    .ctx
                    .sizeof_type(&type_name)
                    .ok_or_else(|| EvalError::TypeNotFound(type_name))?;
                Ok(EvalResult::UInt(sz as u64))
            }
            "bool" => {
                need(1)?;
                Ok(EvalResult::Bool(eval_arg(0)?.to_bool()))
            }
            "not" => {
                need(1)?;
                Ok(EvalResult::Bool(!eval_arg(0)?.to_bool()))
            }
            "is_zero" => {
                need(1)?;
                Ok(EvalResult::Bool(eval_arg(0)?.to_u64()? == 0))
            }
            "pow2" => {
                // pow2(n) → 2^n
                need(1)?;
                let n = eval_arg(0)?.to_u64()?;
                if n >= 64 {
                    return Err(EvalError::ShiftOutOfRange(n));
                }
                Ok(EvalResult::UInt(1u64 << n))
            }
            "log2" => {
                // log2(n) → floor(log2(n))
                need(1)?;
                let n = eval_arg(0)?.to_u64()?;
                if n == 0 {
                    return Ok(EvalResult::UInt(0));
                }
                Ok(EvalResult::UInt(63 - u64::from(n.leading_zeros())))
            }
            _ => Err(EvalError::UnknownFunction(name.to_string())),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExpressionCache
// ─────────────────────────────────────────────────────────────────────────────

/// A simple cache for expression results keyed by a hash of the expression
/// and its context snapshot.  Useful when the same expression is evaluated
/// many times (e.g. inside an array).
#[derive(Debug, Default)]
pub struct ExpressionCache {
    cache: HashMap<String, EvalResult>,
}

impl ExpressionCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a cached result by expression key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&EvalResult> {
        self.cache.get(key)
    }

    /// Insert a result.
    pub fn insert(&mut self, key: impl Into<String>, result: EvalResult) {
        self.cache.insert(key.into(), result);
    }

    /// Number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Clear all cached entries.
    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(fields: &[(&str, u64)]) -> EvalContext {
        let mut ctx = EvalContext::new();
        for (name, val) in fields {
            ctx.set_u64(*name, *val);
        }
        ctx
    }

    fn eval(expr: &TemplateExpr, ctx: &EvalContext) -> EvalResult {
        TemplateExprEval::new(ctx).eval(expr).unwrap()
    }

    #[test]
    fn test_lit_uint() {
        let ctx = EvalContext::new();
        assert_eq!(eval(&TemplateExpr::LitUInt(42), &ctx), EvalResult::UInt(42));
    }

    #[test]
    fn test_field_ref() {
        let ctx = ctx_with(&[("x", 100)]);
        assert_eq!(eval(&TemplateExpr::field("x"), &ctx), EvalResult::UInt(100));
    }

    #[test]
    fn test_add() {
        let ctx = ctx_with(&[("a", 3), ("b", 4)]);
        let expr = TemplateExpr::add(TemplateExpr::field("a"), TemplateExpr::field("b"));
        assert_eq!(eval(&expr, &ctx), EvalResult::UInt(7));
    }

    #[test]
    fn test_sub_wrapping() {
        let ctx = ctx_with(&[("a", 0), ("b", 1)]);
        let expr = TemplateExpr::Sub(
            Box::new(TemplateExpr::field("a")),
            Box::new(TemplateExpr::field("b")),
        );
        assert_eq!(eval(&expr, &ctx), EvalResult::UInt(u64::MAX));
    }

    #[test]
    fn test_div_by_zero() {
        let ctx = ctx_with(&[("a", 10), ("b", 0)]);
        let expr = TemplateExpr::Div(
            Box::new(TemplateExpr::field("a")),
            Box::new(TemplateExpr::field("b")),
        );
        assert!(matches!(
            TemplateExprEval::new(&ctx).eval(&expr),
            Err(EvalError::DivisionByZero)
        ));
    }

    #[test]
    fn test_comparison_eq() {
        let ctx = ctx_with(&[("x", 5)]);
        let expr = TemplateExpr::eq(TemplateExpr::field("x"), TemplateExpr::LitUInt(5));
        assert_eq!(eval(&expr, &ctx), EvalResult::Bool(true));
    }

    #[test]
    fn test_comparison_ne() {
        let ctx = ctx_with(&[("x", 5)]);
        let expr = TemplateExpr::ne(TemplateExpr::field("x"), TemplateExpr::LitUInt(6));
        assert_eq!(eval(&expr, &ctx), EvalResult::Bool(true));
    }

    #[test]
    fn test_logical_and_short_circuit() {
        // If a is false, b must not be evaluated (b references missing field)
        let _ctx = ctx_with(&[("a", 0)]);
        let _expr = TemplateExpr::and(
            TemplateExpr::eq(TemplateExpr::field("a"), TemplateExpr::LitUInt(0)),
            TemplateExpr::field("missing"),
        );
        // The And is false (0 == 0 is true but... wait, 0 == 0 → true)
        // Let's use a=1 case where first is false (a==99)
        let ctx2 = ctx_with(&[("a", 5)]);
        let expr2 = TemplateExpr::and(
            TemplateExpr::eq(TemplateExpr::field("a"), TemplateExpr::LitUInt(99)),
            TemplateExpr::field("missing"),
        );
        assert_eq!(
            TemplateExprEval::new(&ctx2).eval(&expr2).unwrap(),
            EvalResult::Bool(false)
        );
    }

    #[test]
    fn test_ternary() {
        let ctx = ctx_with(&[("flag", 1)]);
        let expr = TemplateExpr::ternary(
            TemplateExpr::eq(TemplateExpr::field("flag"), TemplateExpr::LitUInt(1)),
            TemplateExpr::LitUInt(42),
            TemplateExpr::LitUInt(0),
        );
        assert_eq!(eval(&expr, &ctx), EvalResult::UInt(42));
    }

    #[test]
    fn test_bitwise_ops() {
        let ctx = ctx_with(&[("x", 0b1010)]);
        let and_expr = TemplateExpr::bit_and(
            TemplateExpr::field("x"),
            TemplateExpr::LitUInt(0b1100),
        );
        assert_eq!(eval(&and_expr, &ctx), EvalResult::UInt(0b1000));
    }

    #[test]
    fn test_shl() {
        let ctx = ctx_with(&[("x", 1)]);
        let expr = TemplateExpr::Shl(
            Box::new(TemplateExpr::field("x")),
            Box::new(TemplateExpr::LitUInt(4)),
        );
        assert_eq!(eval(&expr, &ctx), EvalResult::UInt(16));
    }

    #[test]
    fn test_fn_min_max() {
        let ctx = ctx_with(&[("a", 3), ("b", 7)]);
        let min_e = TemplateExpr::Call {
            name: "min".to_string(),
            args: vec![TemplateExpr::field("a"), TemplateExpr::field("b")],
        };
        assert_eq!(eval(&min_e, &ctx), EvalResult::UInt(3));
        let max_e = TemplateExpr::Call {
            name: "max".to_string(),
            args: vec![TemplateExpr::field("a"), TemplateExpr::field("b")],
        };
        assert_eq!(eval(&max_e, &ctx), EvalResult::UInt(7));
    }

    #[test]
    fn test_fn_align() {
        let ctx = EvalContext::new();
        let expr = TemplateExpr::Call {
            name: "align".to_string(),
            args: vec![TemplateExpr::LitUInt(5), TemplateExpr::LitUInt(4)],
        };
        assert_eq!(eval(&expr, &ctx), EvalResult::UInt(8));
    }

    #[test]
    fn test_fn_bits() {
        let ctx = ctx_with(&[("flags", 0b1011_1010)]);
        let expr = TemplateExpr::Call {
            name: "bits".to_string(),
            args: vec![
                TemplateExpr::field("flags"),
                TemplateExpr::LitUInt(2),
                TemplateExpr::LitUInt(4),
            ],
        };
        // bits 2..5 of 0b10111010 = 0b1110
        assert_eq!(eval(&expr, &ctx), EvalResult::UInt(0b1110));
    }

    #[test]
    fn test_fn_sizeof() {
        let mut ctx = EvalContext::new();
        ctx.register_sizeof("DWORD", 4);
        let expr = TemplateExpr::Call {
            name: "sizeof".to_string(),
            args: vec![TemplateExpr::LitStr("DWORD".to_string())],
        };
        assert_eq!(eval(&expr, &ctx), EvalResult::UInt(4));
    }

    #[test]
    fn test_fn_unknown() {
        let ctx = EvalContext::new();
        let expr = TemplateExpr::Call {
            name: "bogus".to_string(),
            args: vec![],
        };
        assert!(matches!(
            TemplateExprEval::new(&ctx).eval(&expr),
            Err(EvalError::UnknownFunction(_))
        ));
    }

    #[test]
    fn test_field_missing() {
        let ctx = EvalContext::new();
        let expr = TemplateExpr::field("nope");
        assert!(matches!(
            TemplateExprEval::new(&ctx).eval(&expr),
            Err(EvalError::FieldNotFound(_))
        ));
    }

    #[test]
    fn test_expression_cache() {
        let mut cache = ExpressionCache::new();
        assert!(cache.is_empty());
        cache.insert("key1", EvalResult::UInt(42));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("key1"), Some(&EvalResult::UInt(42)));
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_fn_log2() {
        let ctx = EvalContext::new();
        let expr = TemplateExpr::Call {
            name: "log2".to_string(),
            args: vec![TemplateExpr::LitUInt(8)],
        };
        assert_eq!(eval(&expr, &ctx), EvalResult::UInt(3));
    }
}
