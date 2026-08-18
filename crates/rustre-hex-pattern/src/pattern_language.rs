//! Pattern language parser and evaluator for the hex-pattern crate.
//!
//! Provides [`PatternLanguage`] as the main facade, [`ProgramAst`] as the
//! top-level abstract-syntax tree, [`TypeDef`] and a visitor trait for type
//! declarations, [`ExprEval`] for expression evaluation, [`BuiltinType`] for
//! primitive numeric types, [`UserDefinedType`] for struct/enum/union types,
//! and [`StructLayout`] for computing the memory layout of a struct.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the pattern-language module.
#[derive(Debug, Error)]
pub enum PatternLangError {
    #[error("parse error at line {line}: {msg}")]
    Parse { line: u32, msg: String },
    #[error("undefined type: {0}")]
    UndefinedType(String),
    #[error("type redefined: {0}")]
    TypeRedefined(String),
    #[error("evaluation error: {0}")]
    Eval(String),
    #[error("layout error in type {ty}: {msg}")]
    Layout { ty: String, msg: String },
    #[error("out-of-bounds read at offset {offset} (buffer {len} bytes)")]
    OutOfBounds { offset: usize, len: usize },
    #[error("unsupported operation: {0}")]
    Unsupported(String),
}

pub type PatternResult<T> = Result<T, PatternLangError>;

// ---------------------------------------------------------------------------
// BuiltinType
// ---------------------------------------------------------------------------

/// Primitive types natively understood by the pattern language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BuiltinType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Bool,
    Char,
}

impl BuiltinType {
    /// Size in bytes.
    #[must_use]
    pub const fn size(self) -> usize {
        match self {
            Self::U8 | Self::I8 | Self::Bool | Self::Char => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 | Self::F32 => 4,
            Self::U64 | Self::I64 | Self::F64 => 8,
        }
    }

    /// True when this is a signed integer or float.
    #[must_use]
    pub const fn is_signed(self) -> bool {
        matches!(
            self,
            Self::I8 | Self::I16 | Self::I32 | Self::I64 | Self::F32 | Self::F64
        )
    }

    /// True when this is a floating-point type.
    #[must_use]
    pub const fn is_float(self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    /// String representation used in pattern source.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Bool => "bool",
            Self::Char => "char",
        }
    }

    /// Parse from keyword string.
    #[must_use]
    pub fn from_keyword(s: &str) -> Option<Self> {
        match s {
            "u8" => Some(Self::U8),
            "u16" => Some(Self::U16),
            "u32" => Some(Self::U32),
            "u64" => Some(Self::U64),
            "i8" => Some(Self::I8),
            "i16" => Some(Self::I16),
            "i32" => Some(Self::I32),
            "i64" => Some(Self::I64),
            "f32" => Some(Self::F32),
            "f64" => Some(Self::F64),
            "bool" => Some(Self::Bool),
            "char" => Some(Self::Char),
            _ => None,
        }
    }
}

impl fmt::Display for BuiltinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.keyword())
    }
}

// ---------------------------------------------------------------------------
// TypeRef — reference to either a builtin or a user-defined type
// ---------------------------------------------------------------------------

/// A reference to a type (either built-in or user-defined).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeRef {
    Builtin(BuiltinType),
    Named(String),
    Array { element: Box<TypeRef>, count: u64 },
    Pointer { pointee: Box<TypeRef> },
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin(b) => write!(f, "{b}"),
            Self::Named(n) => write!(f, "{n}"),
            Self::Array { element, count } => write!(f, "{element}[{count}]"),
            Self::Pointer { pointee } => write!(f, "*{pointee}"),
        }
    }
}

// ---------------------------------------------------------------------------
// StructField / EnumVariant
// ---------------------------------------------------------------------------

/// One field in a struct or union.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub ty: TypeRef,
    /// Optional bit-field width (None = whole field).
    pub bitfield: Option<u8>,
    /// Optional compile-time condition for optional fields.
    pub condition: Option<String>,
    pub comment: Option<String>,
}

impl StructField {
    #[must_use]
    pub fn new(name: impl Into<String>, ty: TypeRef) -> Self {
        Self {
            name: name.into(),
            ty,
            bitfield: None,
            condition: None,
            comment: None,
        }
    }
}

/// One variant in an enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
    pub comment: Option<String>,
}

// ---------------------------------------------------------------------------
// UserDefinedType
// ---------------------------------------------------------------------------

/// Kind of user-defined type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeKind {
    Struct,
    Union,
    Enum,
    Bitfield,
}

/// A type declared in pattern source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDefinedType {
    pub name: String,
    pub kind: TypeKind,
    pub fields: Vec<StructField>,
    pub enum_variants: Vec<EnumVariant>,
    pub underlying_type: Option<BuiltinType>,
    pub doc: Option<String>,
}

impl UserDefinedType {
    /// Create a new struct type.
    #[must_use]
    pub fn new_struct(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: TypeKind::Struct,
            fields: Vec::new(),
            enum_variants: Vec::new(),
            underlying_type: None,
            doc: None,
        }
    }

    /// Create a new enum type.
    #[must_use]
    pub fn new_enum(name: impl Into<String>, underlying: BuiltinType) -> Self {
        Self {
            name: name.into(),
            kind: TypeKind::Enum,
            fields: Vec::new(),
            enum_variants: Vec::new(),
            underlying_type: Some(underlying),
            doc: None,
        }
    }

    /// Add a struct field.
    pub fn add_field(&mut self, field: StructField) {
        self.fields.push(field);
    }

    /// Add an enum variant.
    pub fn add_variant(&mut self, name: impl Into<String>, value: i64) {
        self.enum_variants.push(EnumVariant {
            name: name.into(),
            value,
            comment: None,
        });
    }

    /// Look up a variant by value.
    #[must_use]
    pub fn variant_name(&self, value: i64) -> Option<&str> {
        self.enum_variants
            .iter()
            .find(|v| v.value == value)
            .map(|v| v.name.as_str())
    }
}

// ---------------------------------------------------------------------------
// TypeDef & Visitor
// ---------------------------------------------------------------------------

/// A top-level type declaration statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeDef {
    Builtin(BuiltinType),
    UserDefined(UserDefinedType),
    Alias { name: String, target: TypeRef },
}

impl TypeDef {
    /// The declared name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Builtin(b) => b.keyword(),
            Self::UserDefined(u) => &u.name,
            Self::Alias { name, .. } => name,
        }
    }
}

/// Visitor over a [`TypeDef`] node.
pub trait TypeDefVisitor {
    fn visit_builtin(&mut self, _ty: BuiltinType) {}
    fn visit_user_defined(&mut self, _ty: &UserDefinedType) {}
    fn visit_alias(&mut self, _name: &str, _target: &TypeRef) {}

    /// Dispatch to the correct visit method.
    fn visit(&mut self, def: &TypeDef) {
        match def {
            TypeDef::Builtin(b) => self.visit_builtin(*b),
            TypeDef::UserDefined(u) => self.visit_user_defined(u),
            TypeDef::Alias { name, target } => self.visit_alias(name, target),
        }
    }
}

// ---------------------------------------------------------------------------
// Expression AST
// ---------------------------------------------------------------------------

/// An expression in the pattern language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expr {
    /// Integer literal.
    Int(i64),
    /// Float literal.
    Float(f64),
    /// Boolean literal.
    Bool(bool),
    /// Variable reference.
    Var(String),
    /// Binary operation.
    BinOp {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// Unary operation.
    UnOp { op: UnOp, operand: Box<Expr> },
    /// Field access: `expr.field`.
    Field { base: Box<Expr>, field: String },
    /// Array index: `expr[n]`.
    Index { base: Box<Expr>, index: Box<Expr> },
    /// Cast expression.
    Cast { ty: TypeRef, expr: Box<Expr> },
    /// Size-of operator.
    SizeOf(TypeRef),
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    LogAnd,
    LogOr,
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnOp {
    Neg,
    Not,
    BitNot,
}

// ---------------------------------------------------------------------------
// ExprEval
// ---------------------------------------------------------------------------

/// Evaluator for constant-folding expressions.
///
/// Only literal integer/bool expressions and simple arithmetic are supported
/// without a full interpreter context; variable references require an
/// environment map.
#[derive(Debug, Clone, Default)]
pub struct ExprEval {
    /// Variable bindings: name → integer value.
    env: HashMap<String, i64>,
}

impl ExprEval {
    /// Create an evaluator with an empty environment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a variable.
    pub fn bind(&mut self, name: impl Into<String>, value: i64) {
        self.env.insert(name.into(), value);
    }

    /// Evaluate an expression to an integer.
    pub fn eval_int(&self, expr: &Expr) -> PatternResult<i64> {
        match expr {
            Expr::Int(n) => Ok(*n),
            Expr::Bool(b) => Ok(if *b { 1 } else { 0 }),
            Expr::Float(f) => Ok(*f as i64),
            Expr::Var(name) => self
                .env
                .get(name)
                .copied()
                .ok_or_else(|| PatternLangError::Eval(format!("undefined variable: {name}"))),
            Expr::BinOp { op, lhs, rhs } => {
                let l = self.eval_int(lhs)?;
                let r = self.eval_int(rhs)?;
                self.apply_binop(*op, l, r)
            }
            Expr::UnOp { op, operand } => {
                let v = self.eval_int(operand)?;
                match op {
                    UnOp::Neg => Ok(v.wrapping_neg()),
                    UnOp::Not => Ok(if v == 0 { 1 } else { 0 }),
                    UnOp::BitNot => Ok(!v),
                }
            }
            Expr::SizeOf(ty) => self.eval_sizeof(ty),
            Expr::Cast { ty: _, expr } => self.eval_int(expr),
            _ => Err(PatternLangError::Unsupported(
                "complex expression in integer context".into(),
            )),
        }
    }

    fn apply_binop(&self, op: BinOp, l: i64, r: i64) -> PatternResult<i64> {
        match op {
            BinOp::Add => Ok(l.wrapping_add(r)),
            BinOp::Sub => Ok(l.wrapping_sub(r)),
            BinOp::Mul => Ok(l.wrapping_mul(r)),
            BinOp::Div => {
                if r == 0 {
                    Err(PatternLangError::Eval("division by zero".into()))
                } else {
                    Ok(l / r)
                }
            }
            BinOp::Rem => {
                if r == 0 {
                    Err(PatternLangError::Eval("remainder by zero".into()))
                } else {
                    Ok(l % r)
                }
            }
            BinOp::And => Ok(l & r),
            BinOp::Or => Ok(l | r),
            BinOp::Xor => Ok(l ^ r),
            BinOp::Shl => Ok(l << (r & 63)),
            BinOp::Shr => Ok(l >> (r & 63)),
            BinOp::Eq => Ok(if l == r { 1 } else { 0 }),
            BinOp::Ne => Ok(if l != r { 1 } else { 0 }),
            BinOp::Lt => Ok(if l < r { 1 } else { 0 }),
            BinOp::Le => Ok(if l <= r { 1 } else { 0 }),
            BinOp::Gt => Ok(if l > r { 1 } else { 0 }),
            BinOp::Ge => Ok(if l >= r { 1 } else { 0 }),
            BinOp::LogAnd => Ok(if l != 0 && r != 0 { 1 } else { 0 }),
            BinOp::LogOr => Ok(if l != 0 || r != 0 { 1 } else { 0 }),
        }
    }

    fn eval_sizeof(&self, ty: &TypeRef) -> PatternResult<i64> {
        match ty {
            TypeRef::Builtin(b) => Ok(b.size() as i64),
            TypeRef::Pointer { .. } => Ok(8), // assume 64-bit
            TypeRef::Array { element, count } => {
                let elem_size = self.eval_sizeof(element)?;
                let count_i64 = i64::try_from(*count).map_err(|_| {
                    PatternLangError::Eval(format!("array count {count} overflows i64"))
                })?;
                elem_size.checked_mul(count_i64).ok_or_else(|| {
                    PatternLangError::Eval(format!("sizeof array overflow: {elem_size} * {count_i64}"))
                })
            }
            TypeRef::Named(_) => Err(PatternLangError::Unsupported(
                "sizeof user-defined type requires type context".into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Statement / ProgramAst
// ---------------------------------------------------------------------------

/// A single top-level statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Statement {
    /// Type declaration.
    TypeDecl(TypeDef),
    /// Variable declaration with optional initialiser.
    VarDecl {
        ty: TypeRef,
        name: String,
        init: Option<Expr>,
    },
    /// Assignment statement.
    Assign { target: String, value: Expr },
    /// `if` statement with optional `else` branch.
    If {
        condition: Expr,
        then_block: Vec<Statement>,
        else_block: Vec<Statement>,
    },
    /// `for` loop.
    For {
        var: String,
        from: Expr,
        to: Expr,
        body: Vec<Statement>,
    },
    /// Expression statement (e.g. function call).
    Expr(Expr),
}

/// The top-level AST of a parsed pattern program.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramAst {
    pub statements: Vec<Statement>,
    /// Source file path or name (for diagnostics).
    pub source: Option<String>,
}

impl ProgramAst {
    /// Create an empty program.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a statement.
    pub fn push(&mut self, stmt: Statement) {
        self.statements.push(stmt);
    }

    /// Iterate over all type declarations.
    pub fn type_decls(&self) -> impl Iterator<Item = &TypeDef> {
        self.statements.iter().filter_map(|s| {
            if let Statement::TypeDecl(td) = s {
                Some(td)
            } else {
                None
            }
        })
    }

    /// Number of statements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.statements.len()
    }

    /// True when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }
}

// ---------------------------------------------------------------------------
// StructLayout
// ---------------------------------------------------------------------------

/// Layout information for a single field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldLayout {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub padding_before: usize,
}

/// The computed memory layout of a struct or union.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructLayout {
    pub type_name: String,
    pub total_size: usize,
    pub alignment: usize,
    pub fields: Vec<FieldLayout>,
}

impl StructLayout {
    /// Compute the layout for a [`UserDefinedType`] given a type environment.
    pub fn compute(
        ty: &UserDefinedType,
        type_env: &HashMap<String, usize>,
    ) -> PatternResult<Self> {
        match ty.kind {
            TypeKind::Struct => Self::compute_struct(ty, type_env),
            TypeKind::Union => Self::compute_union(ty, type_env),
            TypeKind::Enum => {
                let size = ty
                    .underlying_type
                    .map(BuiltinType::size)
                    .unwrap_or(4);
                Ok(StructLayout {
                    type_name: ty.name.clone(),
                    total_size: size,
                    alignment: size,
                    fields: Vec::new(),
                })
            }
            TypeKind::Bitfield => Err(PatternLangError::Unsupported("bitfield layout".into())),
        }
    }

    fn compute_struct(
        ty: &UserDefinedType,
        type_env: &HashMap<String, usize>,
    ) -> PatternResult<Self> {
        let mut fields = Vec::new();
        let mut offset = 0usize;
        let mut max_align = 1usize;

        for field in &ty.fields {
            let size = field_size(&field.ty, type_env)?;
            let align = size.min(8).max(1);
            let padding = (align - offset % align) % align;
            fields.push(FieldLayout {
                name: field.name.clone(),
                offset: offset + padding,
                size,
                padding_before: padding,
            });
            offset += padding + size;
            if align > max_align {
                max_align = align;
            }
        }

        let tail_pad = (max_align - offset % max_align) % max_align;
        let total = offset + tail_pad;

        Ok(StructLayout {
            type_name: ty.name.clone(),
            total_size: total,
            alignment: max_align,
            fields,
        })
    }

    fn compute_union(
        ty: &UserDefinedType,
        type_env: &HashMap<String, usize>,
    ) -> PatternResult<Self> {
        let mut max_size = 0usize;
        let mut max_align = 1usize;
        let mut fields = Vec::new();

        for field in &ty.fields {
            let size = field_size(&field.ty, type_env)?;
            let align = size.min(8).max(1);
            fields.push(FieldLayout {
                name: field.name.clone(),
                offset: 0,
                size,
                padding_before: 0,
            });
            if size > max_size { max_size = size; }
            if align > max_align { max_align = align; }
        }

        let total = (max_size + max_align - 1) / max_align * max_align;
        Ok(StructLayout {
            type_name: ty.name.clone(),
            total_size: total,
            alignment: max_align,
            fields,
        })
    }
}

fn field_size(ty: &TypeRef, env: &HashMap<String, usize>) -> PatternResult<usize> {
    match ty {
        TypeRef::Builtin(b) => Ok(b.size()),
        TypeRef::Pointer { .. } => Ok(8),
        TypeRef::Array { element, count } => {
            let elem = field_size(element, env)?;
            let count_usize = usize::try_from(*count).map_err(|_| {
                PatternLangError::Layout {
                    ty: "<array>".to_string(),
                    msg: format!("array count {count} overflows usize"),
                }
            })?;
            elem.checked_mul(count_usize).ok_or_else(|| PatternLangError::Layout {
                ty: "<array>".to_string(),
                msg: format!("array size overflow: {elem} * {count_usize}"),
            })
        }
        TypeRef::Named(n) => env
            .get(n)
            .copied()
            .ok_or_else(|| PatternLangError::UndefinedType(n.clone())),
    }
}

// ---------------------------------------------------------------------------
// PatternLanguage
// ---------------------------------------------------------------------------

/// Main façade for the pattern language.
///
/// Manages a type environment (builtin + user-defined), an expression
/// evaluator, and a program AST.
#[derive(Debug, Default)]
pub struct PatternLanguage {
    /// Declared user types: name → type.
    user_types: HashMap<String, UserDefinedType>,
    /// Pre-computed sizes for user types (name → byte size).
    type_sizes: HashMap<String, usize>,
    /// Expression evaluator.
    pub evaluator: ExprEval,
    /// The most-recently loaded program.
    pub program: ProgramAst,
}

impl PatternLanguage {
    /// Create a fresh instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a user-defined type.
    pub fn define_type(&mut self, ty: UserDefinedType) -> PatternResult<()> {
        if self.user_types.contains_key(&ty.name) {
            return Err(PatternLangError::TypeRedefined(ty.name));
        }
        let layout = StructLayout::compute(&ty, &self.type_sizes);
        if let Ok(l) = layout {
            self.type_sizes.insert(ty.name.clone(), l.total_size);
        }
        self.user_types.insert(ty.name.clone(), ty);
        Ok(())
    }

    /// Look up a user-defined type.
    #[must_use]
    pub fn get_type(&self, name: &str) -> Option<&UserDefinedType> {
        self.user_types.get(name)
    }

    /// Return the size (in bytes) of a named type.
    #[must_use]
    pub fn type_size(&self, name: &str) -> Option<usize> {
        if let Some(b) = BuiltinType::from_keyword(name) {
            return Some(b.size());
        }
        self.type_sizes.get(name).copied()
    }

    /// Compute the layout for a previously registered type.
    pub fn layout(&self, name: &str) -> PatternResult<StructLayout> {
        let ty = self
            .user_types
            .get(name)
            .ok_or_else(|| PatternLangError::UndefinedType(name.to_string()))?;
        StructLayout::compute(ty, &self.type_sizes)
    }

    /// Evaluate an expression to an integer in the current environment.
    pub fn eval(&self, expr: &Expr) -> PatternResult<i64> {
        self.evaluator.eval_int(expr)
    }

    /// Read a builtin value from `data` at byte `offset` in little-endian order.
    pub fn read_builtin(&self, ty: BuiltinType, data: &[u8], offset: usize) -> PatternResult<i64> {
        let size = ty.size();
        if offset + size > data.len() {
            return Err(PatternLangError::OutOfBounds {
                offset,
                len: data.len(),
            });
        }
        let bytes = &data[offset..offset + size];
        Ok(match ty {
            BuiltinType::U8 => i64::from(bytes[0]),
            BuiltinType::I8 => i64::from(bytes[0] as i8),
            BuiltinType::Bool => i64::from(bytes[0] != 0),
            BuiltinType::Char => i64::from(bytes[0]),
            BuiltinType::U16 => i64::from(u16::from_le_bytes([bytes[0], bytes[1]])),
            BuiltinType::I16 => i64::from(i16::from_le_bytes([bytes[0], bytes[1]])),
            BuiltinType::U32 => i64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
            BuiltinType::I32 => i64::from(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
            BuiltinType::F32 => {
                f64::from(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])) as i64
            }
            BuiltinType::U64 | BuiltinType::I64 | BuiltinType::F64 => {
                let arr: [u8; 8] = bytes.try_into().unwrap();
                i64::from_le_bytes(arr)
            }
        })
    }

    /// Walk all type declarations in `program`, applying `visitor`.
    pub fn visit_type_decls<V: TypeDefVisitor>(&self, visitor: &mut V) {
        for td in self.program.type_decls() {
            visitor.visit(td);
        }
    }

    /// Load a program AST, extracting and registering any type declarations.
    pub fn load_program(&mut self, ast: ProgramAst) -> PatternResult<()> {
        for stmt in &ast.statements {
            if let Statement::TypeDecl(TypeDef::UserDefined(udt)) = stmt {
                if !self.user_types.contains_key(&udt.name) {
                    let layout = StructLayout::compute(udt, &self.type_sizes);
                    if let Ok(l) = &layout {
                        self.type_sizes.insert(udt.name.clone(), l.total_size);
                    }
                    self.user_types.insert(udt.name.clone(), udt.clone());
                }
            }
        }
        self.program = ast;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- BuiltinType ---

    #[test]
    fn test_builtin_size() {
        assert_eq!(BuiltinType::U8.size(), 1);
        assert_eq!(BuiltinType::U16.size(), 2);
        assert_eq!(BuiltinType::U32.size(), 4);
        assert_eq!(BuiltinType::U64.size(), 8);
        assert_eq!(BuiltinType::I8.size(), 1);
        assert_eq!(BuiltinType::F32.size(), 4);
        assert_eq!(BuiltinType::F64.size(), 8);
    }

    #[test]
    fn test_builtin_signed() {
        assert!(!BuiltinType::U32.is_signed());
        assert!(BuiltinType::I32.is_signed());
        assert!(BuiltinType::F64.is_signed());
    }

    #[test]
    fn test_builtin_float() {
        assert!(BuiltinType::F32.is_float());
        assert!(BuiltinType::F64.is_float());
        assert!(!BuiltinType::U32.is_float());
    }

    #[test]
    fn test_builtin_keyword_roundtrip() {
        for &b in &[
            BuiltinType::U8, BuiltinType::U16, BuiltinType::U32, BuiltinType::U64,
            BuiltinType::I8, BuiltinType::I16, BuiltinType::I32, BuiltinType::I64,
            BuiltinType::F32, BuiltinType::F64,
        ] {
            assert_eq!(BuiltinType::from_keyword(b.keyword()), Some(b));
        }
    }

    #[test]
    fn test_builtin_from_keyword_unknown() {
        assert!(BuiltinType::from_keyword("uint128").is_none());
    }

    #[test]
    fn test_builtin_display() {
        assert_eq!(BuiltinType::U32.to_string(), "u32");
    }

    // --- TypeRef ---

    #[test]
    fn test_typeref_display_builtin() {
        let tr = TypeRef::Builtin(BuiltinType::U8);
        assert_eq!(tr.to_string(), "u8");
    }

    #[test]
    fn test_typeref_display_array() {
        let tr = TypeRef::Array {
            element: Box::new(TypeRef::Builtin(BuiltinType::U8)),
            count: 4,
        };
        assert_eq!(tr.to_string(), "u8[4]");
    }

    // --- ExprEval ---

    #[test]
    fn test_eval_int_literal() {
        let e = ExprEval::new();
        assert_eq!(e.eval_int(&Expr::Int(42)).unwrap(), 42);
    }

    #[test]
    fn test_eval_bool_literal() {
        let e = ExprEval::new();
        assert_eq!(e.eval_int(&Expr::Bool(true)).unwrap(), 1);
        assert_eq!(e.eval_int(&Expr::Bool(false)).unwrap(), 0);
    }

    #[test]
    fn test_eval_variable() {
        let mut e = ExprEval::new();
        e.bind("x", 10);
        assert_eq!(e.eval_int(&Expr::Var("x".into())).unwrap(), 10);
    }

    #[test]
    fn test_eval_undefined_variable() {
        let e = ExprEval::new();
        assert!(e.eval_int(&Expr::Var("y".into())).is_err());
    }

    #[test]
    fn test_eval_add() {
        let e = ExprEval::new();
        let expr = Expr::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expr::Int(3)),
            rhs: Box::new(Expr::Int(4)),
        };
        assert_eq!(e.eval_int(&expr).unwrap(), 7);
    }

    #[test]
    fn test_eval_div_by_zero() {
        let e = ExprEval::new();
        let expr = Expr::BinOp {
            op: BinOp::Div,
            lhs: Box::new(Expr::Int(10)),
            rhs: Box::new(Expr::Int(0)),
        };
        assert!(e.eval_int(&expr).is_err());
    }

    #[test]
    fn test_eval_bitwise_and() {
        let e = ExprEval::new();
        let expr = Expr::BinOp {
            op: BinOp::And,
            lhs: Box::new(Expr::Int(0xFF)),
            rhs: Box::new(Expr::Int(0x0F)),
        };
        assert_eq!(e.eval_int(&expr).unwrap(), 0x0F);
    }

    #[test]
    fn test_eval_sizeof_builtin() {
        let e = ExprEval::new();
        let expr = Expr::SizeOf(TypeRef::Builtin(BuiltinType::U64));
        assert_eq!(e.eval_int(&expr).unwrap(), 8);
    }

    #[test]
    fn test_eval_sizeof_array() {
        let e = ExprEval::new();
        let expr = Expr::SizeOf(TypeRef::Array {
            element: Box::new(TypeRef::Builtin(BuiltinType::U32)),
            count: 8,
        });
        assert_eq!(e.eval_int(&expr).unwrap(), 32);
    }

    #[test]
    fn test_eval_negation() {
        let e = ExprEval::new();
        let expr = Expr::UnOp {
            op: UnOp::Neg,
            operand: Box::new(Expr::Int(5)),
        };
        assert_eq!(e.eval_int(&expr).unwrap(), -5);
    }

    #[test]
    fn test_eval_logical_not() {
        let e = ExprEval::new();
        let expr = Expr::UnOp {
            op: UnOp::Not,
            operand: Box::new(Expr::Int(0)),
        };
        assert_eq!(e.eval_int(&expr).unwrap(), 1);
    }

    // --- StructLayout ---

    #[test]
    fn test_struct_layout_simple() {
        let mut s = UserDefinedType::new_struct("Header");
        s.add_field(StructField::new("magic", TypeRef::Builtin(BuiltinType::U32)));
        s.add_field(StructField::new("size", TypeRef::Builtin(BuiltinType::U16)));
        let layout = StructLayout::compute(&s, &HashMap::new()).unwrap();
        // u32 (4) + u16 (2) + 2 pad = 8
        assert_eq!(layout.total_size, 8);
        assert_eq!(layout.fields[0].offset, 0);
        assert_eq!(layout.fields[1].offset, 4);
    }

    #[test]
    fn test_union_layout() {
        let mut u = UserDefinedType {
            name: "Data".into(),
            kind: TypeKind::Union,
            fields: Vec::new(),
            enum_variants: Vec::new(),
            underlying_type: None,
            doc: None,
        };
        u.add_field(StructField::new("a", TypeRef::Builtin(BuiltinType::U8)));
        u.add_field(StructField::new("b", TypeRef::Builtin(BuiltinType::U32)));
        let layout = StructLayout::compute(&u, &HashMap::new()).unwrap();
        assert_eq!(layout.total_size, 4);
    }

    #[test]
    fn test_enum_layout() {
        let e = UserDefinedType::new_enum("Color", BuiltinType::U8);
        let layout = StructLayout::compute(&e, &HashMap::new()).unwrap();
        assert_eq!(layout.total_size, 1);
    }

    // --- UserDefinedType ---

    #[test]
    fn test_enum_variant_lookup() {
        let mut e = UserDefinedType::new_enum("Status", BuiltinType::U8);
        e.add_variant("Ok", 0);
        e.add_variant("Err", 1);
        assert_eq!(e.variant_name(0), Some("Ok"));
        assert_eq!(e.variant_name(99), None);
    }

    // --- PatternLanguage ---

    #[test]
    fn test_define_type() {
        let mut pl = PatternLanguage::new();
        let s = UserDefinedType::new_struct("Hdr");
        pl.define_type(s).unwrap();
        assert!(pl.get_type("Hdr").is_some());
    }

    #[test]
    fn test_define_type_redefined_error() {
        let mut pl = PatternLanguage::new();
        pl.define_type(UserDefinedType::new_struct("Hdr")).unwrap();
        assert!(pl.define_type(UserDefinedType::new_struct("Hdr")).is_err());
    }

    #[test]
    fn test_type_size_builtin() {
        let pl = PatternLanguage::new();
        assert_eq!(pl.type_size("u32"), Some(4));
    }

    #[test]
    fn test_read_u8() {
        let pl = PatternLanguage::new();
        let data = [0xAB, 0xCD];
        assert_eq!(pl.read_builtin(BuiltinType::U8, &data, 0).unwrap(), 0xAB);
    }

    #[test]
    fn test_read_u16_le() {
        let pl = PatternLanguage::new();
        let data = [0x01, 0x02];
        assert_eq!(pl.read_builtin(BuiltinType::U16, &data, 0).unwrap(), 0x0201);
    }

    #[test]
    fn test_read_u32_le() {
        let pl = PatternLanguage::new();
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(
            pl.read_builtin(BuiltinType::U32, &data, 0).unwrap(),
            0x12345678
        );
    }

    #[test]
    fn test_read_out_of_bounds() {
        let pl = PatternLanguage::new();
        assert!(pl.read_builtin(BuiltinType::U32, &[0u8; 2], 0).is_err());
    }

    #[test]
    fn test_load_program() {
        let mut pl = PatternLanguage::new();
        let mut ast = ProgramAst::new();
        let mut s = UserDefinedType::new_struct("Foo");
        s.add_field(StructField::new("x", TypeRef::Builtin(BuiltinType::U8)));
        ast.push(Statement::TypeDecl(TypeDef::UserDefined(s)));
        pl.load_program(ast).unwrap();
        assert!(pl.get_type("Foo").is_some());
    }
}
