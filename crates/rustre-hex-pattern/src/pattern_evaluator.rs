//! Pattern language evaluator for `rustre-hex-pattern`.
//!
//! Implements a small expression language for structured binary patterns:
//! conditions, loops, variable bindings, and built-in functions.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PatternValue
// ---------------------------------------------------------------------------

/// A value in the pattern expression language.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PatternValue {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(String),
    Bytes(Vec<u8>),
    Struct(HashMap<String, Self>),
    Array(Vec<Self>),
    Null,
}

impl PatternValue {
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_bool(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Int(i) => *i != 0,
            Self::Null => false,
            _ => true,
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Bool(_) => "bool",
            Self::Str(_) => "str",
            Self::Bytes(_) => "bytes",
            Self::Struct(_) => "struct",
            Self::Array(_) => "array",
            Self::Null => "null",
        }
    }
}

impl fmt::Display for PatternValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(v) => write!(f, "{v}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Bool(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::Bytes(b) => write!(f, "bytes[{}]", b.len()),
            Self::Struct(_) => write!(f, "struct{{...}}"),
            Self::Array(a) => write!(f, "array[{}]", a.len()),
            Self::Null => write!(f, "null"),
        }
    }
}

// ---------------------------------------------------------------------------
// PatternScope
// ---------------------------------------------------------------------------

/// Variable namespace / scope for pattern expressions.
#[derive(Debug, Clone, Default)]
pub struct PatternScope {
    vars: HashMap<String, PatternValue>,
    parent: Option<Box<Self>>,
}

impl PatternScope {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a child scope.
    #[must_use]
    pub fn child(parent: Self) -> Self {
        Self {
            vars: HashMap::new(),
            parent: Some(Box::new(parent)),
        }
    }

    /// Define a variable in the current scope.
    pub fn define(&mut self, name: impl Into<String>, value: PatternValue) {
        self.vars.insert(name.into(), value);
    }

    /// Maximum scope nesting depth. Prevents stack overflow when an adversary
    /// constructs thousands of nested `PatternScope::child(...)` layers.
    const MAX_SCOPE_DEPTH: usize = 256;

    /// Look up a variable (searches parent scopes iteratively, up to
    /// [`Self::MAX_SCOPE_DEPTH`] levels, to prevent unbounded recursion).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PatternValue> {
        let mut current = self;
        let mut depth = 0usize;
        loop {
            if let Some(v) = current.vars.get(name) {
                return Some(v);
            }
            if depth >= Self::MAX_SCOPE_DEPTH {
                return None;
            }
            match current.parent.as_deref() {
                Some(p) => {
                    current = p;
                    depth += 1;
                }
                None => return None,
            }
        }
    }

    /// Set a variable (in the current scope).
    pub fn set(&mut self, name: impl Into<String>, value: PatternValue) {
        self.vars.insert(name.into(), value);
    }

    /// All variable names in this scope (not parent).
    #[must_use]
    pub fn local_names(&self) -> Vec<&str> {
        self.vars.keys().map(std::string::String::as_str).collect()
    }
}

// ---------------------------------------------------------------------------
// PatternExpression
// ---------------------------------------------------------------------------

/// A pattern language expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PatternExpression {
    /// A literal value.
    Literal(PatternValue),
    /// A variable reference.
    Variable(String),
    /// Binary operation.
    BinOp {
        op: BinOp,
        left: Box<Self>,
        right: Box<Self>,
    },
    /// Unary operation.
    UnaryOp {
        op: UnaryOp,
        operand: Box<Self>,
    },
    /// If-then-else.
    If {
        cond: Box<Self>,
        then_: Box<Self>,
        else_: Box<Self>,
    },
    /// For loop: `for i in 0..count { body }`.
    For {
        var: String,
        count: Box<Self>,
        body: Box<Self>,
    },
    /// While loop.
    While {
        cond: Box<Self>,
        body: Box<Self>,
    },
    /// Variable assignment.
    Let {
        name: String,
        value: Box<Self>,
    },
    /// Block (sequence of expressions, returns last value).
    Block(Vec<Self>),
    /// Function call.
    Call {
        name: String,
        args: Vec<Self>,
    },
    /// Array index.
    Index {
        array: Box<Self>,
        index: Box<Self>,
    },
    /// Struct field access.
    Field {
        object: Box<Self>,
        field: String,
    },
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOp {
    Neg,
    Not,
    BitNot,
}

// ---------------------------------------------------------------------------
// EvalError
// ---------------------------------------------------------------------------

/// Errors from pattern evaluation.
#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    #[error("undefined variable: {0}")]
    UndefinedVariable(String),
    #[error("type error: {0}")]
    TypeError(String),
    #[error("division by zero")]
    DivisionByZero,
    #[error("index out of bounds: {0}")]
    IndexOutOfBounds(usize),
    #[error("unknown function: {0}")]
    UnknownFunction(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("loop limit exceeded")]
    LoopLimitExceeded,
}

// ---------------------------------------------------------------------------
// BuiltinFunctions
// ---------------------------------------------------------------------------

/// Built-in functions available in pattern expressions.
pub struct BuiltinFunctions;

impl BuiltinFunctions {
    /// `exists(name)` — check if a variable is defined.
    #[must_use] 
    pub fn exists(scope: &PatternScope, name: &str) -> PatternValue {
        PatternValue::Bool(scope.get(name).is_some())
    }

    /// `checksum(bytes)` — sum all bytes mod 256.
    #[must_use] 
    pub fn checksum(bytes: &[u8]) -> PatternValue {
        let sum: u32 = bytes.iter().map(|&b| u32::from(b)).sum();
        PatternValue::Int(i64::from(sum % 256))
    }

    /// `entropy(bytes)` — Shannon entropy (0.0–8.0).
    #[must_use] 
    pub fn entropy(bytes: &[u8]) -> PatternValue {
        if bytes.is_empty() {
            return PatternValue::Float(0.0);
        }
        let mut freq = [0u32; 256];
        for &b in bytes {
            freq[b as usize] += 1;
        }
        let n = bytes.len() as f64;
        let ent: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / n;
                -p * p.log2()
            })
            .sum();
        PatternValue::Float(ent)
    }

    /// `string(bytes)` — convert bytes to UTF-8 string (lossy).
    #[must_use] 
    pub fn string(bytes: &[u8]) -> PatternValue {
        PatternValue::Str(String::from_utf8_lossy(bytes).to_string())
    }

    /// `len(array_or_bytes_or_str)` — length.
    #[must_use] 
    pub const fn len(val: &PatternValue) -> PatternValue {
        let n = match val {
            PatternValue::Bytes(b) => b.len(),
            PatternValue::Str(s) => s.len(),
            PatternValue::Array(a) => a.len(),
            _ => 0,
        };
        PatternValue::Int(n as i64)
    }

    /// `min(a, b)` — minimum.
    #[must_use] 
    pub fn min(a: i64, b: i64) -> PatternValue {
        PatternValue::Int(a.min(b))
    }

    /// `max(a, b)` — maximum.
    #[must_use] 
    pub fn max(a: i64, b: i64) -> PatternValue {
        PatternValue::Int(a.max(b))
    }
}

// ---------------------------------------------------------------------------
// PatternDebugger
// ---------------------------------------------------------------------------

/// Debugger for pattern evaluation — records a trace of executed steps.
#[derive(Debug, Clone, Default)]
pub struct PatternDebugger {
    pub trace: Vec<String>,
    pub enabled: bool,
    pub max_trace: usize,
}

impl PatternDebugger {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            trace: Vec::new(),
            enabled: false,
            max_trace: 1000,
        }
    }

    pub const fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn record(&mut self, msg: impl Into<String>) {
        if self.enabled && self.trace.len() < self.max_trace {
            self.trace.push(msg.into());
        }
    }

    pub fn clear(&mut self) {
        self.trace.clear();
    }
}

// ---------------------------------------------------------------------------
// PatternEvaluator
// ---------------------------------------------------------------------------

/// Evaluates pattern expressions against a binary data buffer.
pub struct PatternEvaluator {
    pub data: Vec<u8>,
    pub base_offset: u64,
    pub scope: PatternScope,
    pub debugger: PatternDebugger,
    /// Maximum loop iterations.
    pub loop_limit: usize,
}

impl PatternEvaluator {
    /// Create an evaluator for the given binary data.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            base_offset: 0,
            scope: PatternScope::new(),
            debugger: PatternDebugger::new(),
            loop_limit: 10_000,
        }
    }

    /// Evaluate an expression and return its value.
    ///
    /// # Errors
    /// Returns [`EvalError`] on type errors, undefined variables, etc.
    pub fn eval(&mut self, expr: &PatternExpression) -> Result<PatternValue, EvalError> {
        if self.debugger.enabled {
            self.debugger.record(format!("eval: {expr:?}"));
        }
        match expr {
            PatternExpression::Literal(v) => Ok(v.clone()),
            PatternExpression::Variable(name) => self
                .scope
                .get(name)
                .cloned()
                .ok_or_else(|| EvalError::UndefinedVariable(name.clone())),
            PatternExpression::BinOp { op, left, right } => {
                let l = self.eval(left)?;
                let r = self.eval(right)?;
                self.eval_binop(*op, l, r)
            }
            PatternExpression::UnaryOp { op, operand } => {
                let v = self.eval(operand)?;
                self.eval_unary(*op, v)
            }
            PatternExpression::If { cond, then_, else_ } => {
                let c = self.eval(cond)?;
                if c.as_bool() {
                    self.eval(then_)
                } else {
                    self.eval(else_)
                }
            }
            PatternExpression::Let { name, value } => {
                let v = self.eval(value)?;
                self.scope.define(name.clone(), v.clone());
                Ok(v)
            }
            PatternExpression::Block(exprs) => {
                let mut last = PatternValue::Null;
                for e in exprs {
                    last = self.eval(e)?;
                }
                Ok(last)
            }
            PatternExpression::For { var, count, body } => {
                let n = self
                    .eval(count)?
                    .as_int()
                    .ok_or_else(|| EvalError::TypeError("for count must be int".to_string()))?;
                let n = n.max(0) as usize;
                if n > self.loop_limit {
                    return Err(EvalError::LoopLimitExceeded);
                }
                let mut last = PatternValue::Null;
                for i in 0..n {
                    self.scope.define(var.clone(), PatternValue::Int(i as i64));
                    last = self.eval(body)?;
                }
                Ok(last)
            }
            PatternExpression::While { cond, body } => {
                let mut iters = 0usize;
                let mut last = PatternValue::Null;
                loop {
                    if iters >= self.loop_limit {
                        return Err(EvalError::LoopLimitExceeded);
                    }
                    let c = self.eval(cond)?;
                    if !c.as_bool() {
                        break;
                    }
                    last = self.eval(body)?;
                    iters += 1;
                }
                Ok(last)
            }
            PatternExpression::Call { name, args } => {
                let evaled: Result<Vec<PatternValue>, EvalError> =
                    args.iter().map(|a| self.eval(a)).collect();
                self.eval_call(name, &evaled?)
            }
            PatternExpression::Index { array, index } => {
                let arr = self.eval(array)?;
                let idx = self
                    .eval(index)?
                    .as_int()
                    .ok_or_else(|| EvalError::TypeError("index must be int".to_string()))?
                    as usize;
                match arr {
                    PatternValue::Array(a) => {
                        a.get(idx).cloned().ok_or(EvalError::IndexOutOfBounds(idx))
                    }
                    PatternValue::Bytes(b) => b
                        .get(idx)
                        .map(|&v| PatternValue::Int(i64::from(v)))
                        .ok_or(EvalError::IndexOutOfBounds(idx)),
                    _ => Err(EvalError::TypeError("not indexable".to_string())),
                }
            }
            PatternExpression::Field { object, field } => {
                let obj = self.eval(object)?;
                match obj {
                    PatternValue::Struct(m) => m
                        .get(field.as_str())
                        .cloned()
                        .ok_or_else(|| EvalError::UndefinedVariable(field.clone())),
                    _ => Err(EvalError::TypeError("not a struct".to_string())),
                }
            }
        }
    }

    fn eval_binop(
        &self,
        op: BinOp,
        l: PatternValue,
        r: PatternValue,
    ) -> Result<PatternValue, EvalError> {
        match op {
            BinOp::And => return Ok(PatternValue::Bool(l.as_bool() && r.as_bool())),
            BinOp::Or => return Ok(PatternValue::Bool(l.as_bool() || r.as_bool())),
            _ => {}
        }
        match (l, r) {
            (PatternValue::Int(a), PatternValue::Int(b)) => Ok(match op {
                BinOp::Add => PatternValue::Int(a.wrapping_add(b)),
                BinOp::Sub => PatternValue::Int(a.wrapping_sub(b)),
                BinOp::Mul => PatternValue::Int(a.wrapping_mul(b)),
                BinOp::Div => {
                    if b == 0 {
                        return Err(EvalError::DivisionByZero);
                    }
                    PatternValue::Int(a / b)
                }
                BinOp::Mod => {
                    if b == 0 {
                        return Err(EvalError::DivisionByZero);
                    }
                    PatternValue::Int(a % b)
                }
                BinOp::Eq => PatternValue::Bool(a == b),
                BinOp::Ne => PatternValue::Bool(a != b),
                BinOp::Lt => PatternValue::Bool(a < b),
                BinOp::Le => PatternValue::Bool(a <= b),
                BinOp::Gt => PatternValue::Bool(a > b),
                BinOp::Ge => PatternValue::Bool(a >= b),
                BinOp::BitAnd => PatternValue::Int(a & b),
                BinOp::BitOr => PatternValue::Int(a | b),
                BinOp::BitXor => PatternValue::Int(a ^ b),
                BinOp::Shl => {
                    let shift = u32::try_from(b).map_err(|_| {
                        EvalError::TypeError(format!("shift amount out of range: {b}"))
                    })?;
                    PatternValue::Int(a.wrapping_shl(shift))
                }
                BinOp::Shr => {
                    let shift = u32::try_from(b).map_err(|_| {
                        EvalError::TypeError(format!("shift amount out of range: {b}"))
                    })?;
                    PatternValue::Int(a.wrapping_shr(shift))
                }
                _ => return Err(EvalError::TypeError(format!("op {op:?} on int"))),
            }),
            (PatternValue::Float(a), PatternValue::Float(b)) => Ok(match op {
                BinOp::Add => PatternValue::Float(a + b),
                BinOp::Sub => PatternValue::Float(a - b),
                BinOp::Mul => PatternValue::Float(a * b),
                BinOp::Div => PatternValue::Float(a / b),
                BinOp::Eq => PatternValue::Bool((a - b).abs() < f64::EPSILON),
                BinOp::Ne => PatternValue::Bool((a - b).abs() >= f64::EPSILON),
                BinOp::Lt => PatternValue::Bool(a < b),
                BinOp::Le => PatternValue::Bool(a <= b),
                BinOp::Gt => PatternValue::Bool(a > b),
                BinOp::Ge => PatternValue::Bool(a >= b),
                _ => return Err(EvalError::TypeError("unsupported float op".to_string())),
            }),
            (PatternValue::Str(a), PatternValue::Str(b)) => Ok(match op {
                BinOp::Add => PatternValue::Str(a + &b),
                BinOp::Eq => PatternValue::Bool(a == b),
                BinOp::Ne => PatternValue::Bool(a != b),
                _ => return Err(EvalError::TypeError("unsupported string op".to_string())),
            }),
            (l, r) => Err(EvalError::TypeError(format!(
                "cannot apply {op:?} to {} and {}",
                l.type_name(),
                r.type_name()
            ))),
        }
    }

    fn eval_unary(&self, op: UnaryOp, v: PatternValue) -> Result<PatternValue, EvalError> {
        match (op, v) {
            (UnaryOp::Neg, PatternValue::Int(i)) => Ok(PatternValue::Int(-i)),
            (UnaryOp::Neg, PatternValue::Float(f)) => Ok(PatternValue::Float(-f)),
            (UnaryOp::Not, v) => Ok(PatternValue::Bool(!v.as_bool())),
            (UnaryOp::BitNot, PatternValue::Int(i)) => Ok(PatternValue::Int(!i)),
            (op, v) => Err(EvalError::TypeError(format!(
                "cannot apply {op:?} to {}",
                v.type_name()
            ))),
        }
    }

    fn eval_call(&self, name: &str, args: &[PatternValue]) -> Result<PatternValue, EvalError> {
        match name {
            "checksum" => {
                let bytes = args.first().and_then(|v| v.as_bytes()).unwrap_or(&[]);
                Ok(BuiltinFunctions::checksum(bytes))
            }
            "entropy" => {
                let bytes = args.first().and_then(|v| v.as_bytes()).unwrap_or(&[]);
                Ok(BuiltinFunctions::entropy(bytes))
            }
            "string" => {
                let bytes = args.first().and_then(|v| v.as_bytes()).unwrap_or(&[]);
                Ok(BuiltinFunctions::string(bytes))
            }
            "len" => {
                let val = args.first().unwrap_or(&PatternValue::Null);
                Ok(BuiltinFunctions::len(val))
            }
            "min" => {
                let a = args.first().and_then(PatternValue::as_int).unwrap_or(0);
                let b = args.get(1).and_then(PatternValue::as_int).unwrap_or(0);
                Ok(BuiltinFunctions::min(a, b))
            }
            "max" => {
                let a = args.first().and_then(PatternValue::as_int).unwrap_or(0);
                let b = args.get(1).and_then(PatternValue::as_int).unwrap_or(0);
                Ok(BuiltinFunctions::max(a, b))
            }
            "read_u8" => {
                let raw = args.first().and_then(PatternValue::as_int).unwrap_or(0);
                let off = usize::try_from(raw)
                    .map_err(|_| EvalError::IndexOutOfBounds(0))?;
                self.data
                    .get(off)
                    .map(|&b| PatternValue::Int(i64::from(b)))
                    .ok_or(EvalError::IndexOutOfBounds(off))
            }
            "read_u16le" => {
                let raw = args.first().and_then(PatternValue::as_int).unwrap_or(0);
                let off = usize::try_from(raw)
                    .map_err(|_| EvalError::IndexOutOfBounds(0))?;
                if off.checked_add(2).is_none_or(|end| end > self.data.len()) {
                    return Err(EvalError::IndexOutOfBounds(off));
                }
                Ok(PatternValue::Int(
                    i64::from(u16::from_le_bytes([self.data[off], self.data[off + 1]])),
                ))
            }
            "read_u32le" => {
                let raw = args.first().and_then(PatternValue::as_int).unwrap_or(0);
                let off = usize::try_from(raw)
                    .map_err(|_| EvalError::IndexOutOfBounds(0))?;
                if off.checked_add(4).is_none_or(|end| end > self.data.len()) {
                    return Err(EvalError::IndexOutOfBounds(off));
                }
                let v = u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap());
                Ok(PatternValue::Int(i64::from(v)))
            }
            _ => Err(EvalError::UnknownFunction(name.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(expr: PatternExpression) -> PatternValue {
        let mut e = PatternEvaluator::new(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]);
        e.eval(&expr).unwrap()
    }

    fn int(v: i64) -> PatternExpression {
        PatternExpression::Literal(PatternValue::Int(v))
    }
    fn bool_(v: bool) -> PatternExpression {
        PatternExpression::Literal(PatternValue::Bool(v))
    }
    fn str_(s: &str) -> PatternExpression {
        PatternExpression::Literal(PatternValue::Str(s.to_string()))
    }

    // ── PatternValue ──────────────────────────────────────────────────────

    #[test]
    fn value_as_int() {
        assert_eq!(PatternValue::Int(42).as_int(), Some(42));
        assert_eq!(PatternValue::Str("x".to_string()).as_int(), None);
    }

    #[test]
    fn value_as_bool() {
        assert!(PatternValue::Bool(true).as_bool());
        assert!(!PatternValue::Int(0).as_bool());
        assert!(PatternValue::Int(1).as_bool());
        assert!(!PatternValue::Null.as_bool());
    }

    #[test]
    fn value_display() {
        assert_eq!(PatternValue::Int(7).to_string(), "7");
        assert_eq!(PatternValue::Null.to_string(), "null");
    }

    #[test]
    fn value_type_name() {
        assert_eq!(PatternValue::Int(0).type_name(), "int");
        assert_eq!(PatternValue::Bytes(vec![]).type_name(), "bytes");
    }

    // ── PatternScope ──────────────────────────────────────────────────────

    #[test]
    fn scope_define_and_get() {
        let mut s = PatternScope::new();
        s.define("x", PatternValue::Int(42));
        assert_eq!(s.get("x"), Some(&PatternValue::Int(42)));
    }

    #[test]
    fn scope_undefined_variable() {
        let s = PatternScope::new();
        assert!(s.get("missing").is_none());
    }

    #[test]
    fn scope_child_sees_parent() {
        let mut parent = PatternScope::new();
        parent.define("x", PatternValue::Int(10));
        let child = PatternScope::child(parent);
        assert_eq!(child.get("x"), Some(&PatternValue::Int(10)));
    }

    #[test]
    fn scope_local_names() {
        let mut s = PatternScope::new();
        s.define("a", PatternValue::Null);
        s.define("b", PatternValue::Null);
        let names = s.local_names();
        assert!(names.contains(&"a") && names.contains(&"b"));
    }

    // ── PatternEvaluator: literals ─────────────────────────────────────

    #[test]
    fn eval_int_literal() {
        assert_eq!(eval(int(42)), PatternValue::Int(42));
    }

    #[test]
    fn eval_bool_literal() {
        assert_eq!(eval(bool_(true)), PatternValue::Bool(true));
    }

    #[test]
    fn eval_string_literal() {
        assert_eq!(eval(str_("hello")), PatternValue::Str("hello".to_string()));
    }

    // ── PatternEvaluator: arithmetic ───────────────────────────────────

    #[test]
    fn eval_add() {
        let e = PatternExpression::BinOp {
            op: BinOp::Add,
            left: Box::new(int(3)),
            right: Box::new(int(4)),
        };
        assert_eq!(eval(e), PatternValue::Int(7));
    }

    #[test]
    fn eval_sub() {
        let e = PatternExpression::BinOp {
            op: BinOp::Sub,
            left: Box::new(int(10)),
            right: Box::new(int(3)),
        };
        assert_eq!(eval(e), PatternValue::Int(7));
    }

    #[test]
    fn eval_mul() {
        let e = PatternExpression::BinOp {
            op: BinOp::Mul,
            left: Box::new(int(3)),
            right: Box::new(int(4)),
        };
        assert_eq!(eval(e), PatternValue::Int(12));
    }

    #[test]
    fn eval_div() {
        let e = PatternExpression::BinOp {
            op: BinOp::Div,
            left: Box::new(int(10)),
            right: Box::new(int(2)),
        };
        assert_eq!(eval(e), PatternValue::Int(5));
    }

    #[test]
    fn eval_div_by_zero() {
        let mut ev = PatternEvaluator::new(vec![]);
        let e = PatternExpression::BinOp {
            op: BinOp::Div,
            left: Box::new(int(1)),
            right: Box::new(int(0)),
        };
        assert!(matches!(ev.eval(&e), Err(EvalError::DivisionByZero)));
    }

    // ── PatternEvaluator: comparisons ─────────────────────────────────

    #[test]
    fn eval_eq_true() {
        let e = PatternExpression::BinOp {
            op: BinOp::Eq,
            left: Box::new(int(5)),
            right: Box::new(int(5)),
        };
        assert_eq!(eval(e), PatternValue::Bool(true));
    }

    #[test]
    fn eval_lt() {
        let e = PatternExpression::BinOp {
            op: BinOp::Lt,
            left: Box::new(int(3)),
            right: Box::new(int(5)),
        };
        assert_eq!(eval(e), PatternValue::Bool(true));
    }

    // ── PatternEvaluator: if-then-else ─────────────────────────────────

    #[test]
    fn eval_if_true_branch() {
        let e = PatternExpression::If {
            cond: Box::new(bool_(true)),
            then_: Box::new(int(1)),
            else_: Box::new(int(2)),
        };
        assert_eq!(eval(e), PatternValue::Int(1));
    }

    #[test]
    fn eval_if_false_branch() {
        let e = PatternExpression::If {
            cond: Box::new(bool_(false)),
            then_: Box::new(int(1)),
            else_: Box::new(int(2)),
        };
        assert_eq!(eval(e), PatternValue::Int(2));
    }

    // ── PatternEvaluator: let / variable ──────────────────────────────

    #[test]
    fn eval_let_and_variable() {
        let mut ev = PatternEvaluator::new(vec![]);
        ev.eval(&PatternExpression::Let {
            name: "x".to_string(),
            value: Box::new(int(99)),
        })
        .unwrap();
        let result = ev
            .eval(&PatternExpression::Variable("x".to_string()))
            .unwrap();
        assert_eq!(result, PatternValue::Int(99));
    }

    #[test]
    fn eval_undefined_variable_error() {
        let mut ev = PatternEvaluator::new(vec![]);
        let err = ev.eval(&PatternExpression::Variable("missing".to_string()));
        assert!(matches!(err, Err(EvalError::UndefinedVariable(_))));
    }

    // ── PatternEvaluator: for loop ────────────────────────────────────

    #[test]
    fn eval_for_loop_accumulates() {
        let mut ev = PatternEvaluator::new(vec![]);
        // let sum = 0; for i in 0..3 { sum = sum + i }; sum
        let block = PatternExpression::Block(vec![
            PatternExpression::Let {
                name: "sum".to_string(),
                value: Box::new(int(0)),
            },
            PatternExpression::For {
                var: "i".to_string(),
                count: Box::new(int(4)),
                body: Box::new(PatternExpression::Let {
                    name: "sum".to_string(),
                    value: Box::new(PatternExpression::BinOp {
                        op: BinOp::Add,
                        left: Box::new(PatternExpression::Variable("sum".to_string())),
                        right: Box::new(PatternExpression::Variable("i".to_string())),
                    }),
                }),
            },
            PatternExpression::Variable("sum".to_string()),
        ]);
        let result = ev.eval(&block).unwrap();
        assert_eq!(result, PatternValue::Int(6)); // 0+1+2+3
    }

    // ── BuiltinFunctions ──────────────────────────────────────────────

    #[test]
    fn builtin_checksum() {
        let v = BuiltinFunctions::checksum(&[0x01, 0x02, 0x03]);
        assert_eq!(v, PatternValue::Int(6));
    }

    #[test]
    fn builtin_entropy_uniform() {
        if let PatternValue::Float(e) = BuiltinFunctions::entropy(&[0u8; 256]) {
            assert_eq!(e, 0.0);
        }
    }

    #[test]
    fn builtin_string() {
        let v = BuiltinFunctions::string(b"hello");
        assert_eq!(v, PatternValue::Str("hello".to_string()));
    }

    #[test]
    fn builtin_len_bytes() {
        let v = BuiltinFunctions::len(&PatternValue::Bytes(vec![1, 2, 3]));
        assert_eq!(v, PatternValue::Int(3));
    }

    // ── Built-in function calls ───────────────────────────────────────

    #[test]
    fn call_read_u8() {
        let mut ev = PatternEvaluator::new(vec![0xDE, 0xAD]);
        let e = PatternExpression::Call {
            name: "read_u8".to_string(),
            args: vec![int(1)],
        };
        assert_eq!(ev.eval(&e).unwrap(), PatternValue::Int(0xAD));
    }

    #[test]
    fn call_read_u32le() {
        let mut ev = PatternEvaluator::new(vec![0x01, 0x00, 0x00, 0x00]);
        let e = PatternExpression::Call {
            name: "read_u32le".to_string(),
            args: vec![int(0)],
        };
        assert_eq!(ev.eval(&e).unwrap(), PatternValue::Int(1));
    }

    #[test]
    fn call_unknown_function() {
        let mut ev = PatternEvaluator::new(vec![]);
        let e = PatternExpression::Call {
            name: "nonexistent".to_string(),
            args: vec![],
        };
        assert!(matches!(ev.eval(&e), Err(EvalError::UnknownFunction(_))));
    }

    // ── PatternDebugger ───────────────────────────────────────────────

    #[test]
    fn debugger_records_when_enabled() {
        let mut d = PatternDebugger::new();
        d.enable();
        d.record("step 1");
        assert_eq!(d.trace.len(), 1);
    }

    #[test]
    fn debugger_no_record_when_disabled() {
        let mut d = PatternDebugger::new();
        d.record("step 1");
        assert!(d.trace.is_empty());
    }
}
