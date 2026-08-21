//! CIL / MSIL → C# AST decompiler.
//!
//! Converts a sequence of decoded CIL instructions into a high-level C# AST
//! representation and then pretty-prints it.  Covers:
//! - `CSharpAst` — node types for expressions and statements
//! - `MethodDecompiler` — entry point for a single method body
//! - `ExpressionBuilder` — stack-machine → expression-tree
//! - `StatementBuilder` — block-/exception-structured statements
//! - `TypePrinter` — renders C# type names from metadata tokens
//! - `AsyncMethodRecovery` — detects and restores async state-machine patterns
//! - `LinqRecovery` — detects LINQ query patterns

use std::collections::HashMap;
use std::fmt;

use crate::{CilDecodeError, CilInstr};
use std::fmt::Write as _;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced during CIL decompilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompileError {
    EmptyMethod,
    StackUnderflow { op: String },
    UnsupportedOpcode(String),
    InvalidMetadataToken(u32),
    MissingType(u32),
    Other(String),
}

impl fmt::Display for DecompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMethod => write!(f, "method body is empty"),
            Self::StackUnderflow { op } => write!(f, "stack underflow at {op}"),
            Self::UnsupportedOpcode(s) => write!(f, "unsupported opcode: {s}"),
            Self::InvalidMetadataToken(t) => write!(f, "invalid metadata token {t:#010x}"),
            Self::MissingType(t) => write!(f, "missing type for token {t:#010x}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ── CSharpAst ─────────────────────────────────────────────────────────────────

/// A C# expression node.
#[derive(Debug, Clone, PartialEq)]
pub enum CSharpExpr {
    /// Integer literal.
    IntLit(i64),
    /// Float literal.
    FloatLit(f64),
    /// String literal.
    StringLit(String),
    /// `null` literal.
    Null,
    /// Local variable reference.
    Local(String),
    /// Argument reference.
    Arg(String),
    /// Field access: `obj.field`.
    Field { obj: Box<Self>, field: String },
    /// Static field access: `Type.field`.
    StaticField { type_name: String, field: String },
    /// Method call: `obj.method(args)`.
    Call {
        obj: Box<Self>,
        method: String,
        args: Vec<Self>,
    },
    /// Static method call: `Type.method(args)`.
    StaticCall {
        type_name: String,
        method: String,
        args: Vec<Self>,
    },
    /// Virtual method call: `obj.method(args)`.
    VirtCall {
        obj: Box<Self>,
        method: String,
        args: Vec<Self>,
    },
    /// Object creation: `new Type(args)`.
    NewObj {
        type_name: String,
        args: Vec<Self>,
    },
    /// Array creation: `new T[n]`.
    NewArray {
        elem_type: String,
        length: Box<Self>,
    },
    /// Array element access: `arr[idx]`.
    ArrayElem {
        arr: Box<Self>,
        idx: Box<Self>,
    },
    /// Binary arithmetic / comparison: `lhs op rhs`.
    BinOp {
        op: BinOpKind,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// Unary: `op expr`.
    UnaryOp {
        op: UnaryOpKind,
        expr: Box<Self>,
    },
    /// Cast: `(Type)expr`.
    Cast {
        target_type: String,
        expr: Box<Self>,
    },
    /// Type check: `expr is Type`.
    IsInst {
        expr: Box<Self>,
        type_name: String,
    },
    /// Conditional: `cond ? then : else`.
    Ternary {
        cond: Box<Self>,
        then: Box<Self>,
        else_: Box<Self>,
    },
    /// LINQ query expression placeholder.
    LinqQuery(String),
    /// Await expression.
    Await(Box<Self>),
    /// Default value.
    Default(String),
}

impl fmt::Display for CSharpExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntLit(n) => write!(f, "{n}"),
            Self::FloatLit(v) => write!(f, "{v}"),
            Self::StringLit(s) => write!(f, "\"{s}\""),
            Self::Null => write!(f, "null"),
            Self::Local(n) | Self::Arg(n) => write!(f, "{n}"),
            Self::Field { obj, field } => write!(f, "{obj}.{field}"),
            Self::StaticField { type_name, field } => write!(f, "{type_name}.{field}"),
            Self::Call { obj, method, args } | Self::VirtCall { obj, method, args } => {
                write!(f, "{obj}.{method}(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            Self::StaticCall {
                type_name,
                method,
                args,
            } => {
                write!(f, "{type_name}.{method}(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            Self::NewObj { type_name, args } => {
                write!(f, "new {type_name}(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            Self::NewArray { elem_type, length } => write!(f, "new {elem_type}[{length}]"),
            Self::ArrayElem { arr, idx } => write!(f, "{arr}[{idx}]"),
            Self::BinOp { op, lhs, rhs } => write!(f, "({lhs} {op} {rhs})"),
            Self::UnaryOp { op, expr } => write!(f, "{op}{expr}"),
            Self::Cast { target_type, expr } => write!(f, "({target_type}){expr}"),
            Self::IsInst { expr, type_name } => write!(f, "{expr} is {type_name}"),
            Self::Ternary { cond, then, else_ } => write!(f, "{cond} ? {then} : {else_}"),
            Self::LinqQuery(s) => write!(f, "{s}"),
            Self::Await(e) => write!(f, "await {e}"),
            Self::Default(t) => write!(f, "default({t})"),
        }
    }
}

/// Binary operator kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOpKind {
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
}

impl fmt::Display for BinOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Rem => "%",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        };
        write!(f, "{s}")
    }
}

/// Unary operator kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOpKind {
    Neg,
    Not,
}

impl fmt::Display for UnaryOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Neg => write!(f, "-"),
            Self::Not => write!(f, "!"),
        }
    }
}

// ── CSharpStmt ────────────────────────────────────────────────────────────────

/// A C# statement node.
#[derive(Debug, Clone, PartialEq)]
pub enum CSharpStmt {
    /// `local = expr;`
    Assign { target: String, value: CSharpExpr },
    /// `field.member = expr;`
    FieldAssign {
        target: Box<CSharpExpr>,
        value: CSharpExpr,
    },
    /// Expression statement.
    Expr(CSharpExpr),
    /// `return expr;`
    Return(Option<CSharpExpr>),
    /// `if (cond) { then } else { else_ }`
    If {
        cond: CSharpExpr,
        then: Vec<Self>,
        else_: Vec<Self>,
    },
    /// `while (cond) { body }`
    While {
        cond: CSharpExpr,
        body: Vec<Self>,
    },
    /// `for (init; cond; inc) { body }`
    For {
        init: Option<Box<Self>>,
        cond: Option<CSharpExpr>,
        inc: Option<Box<Self>>,
        body: Vec<Self>,
    },
    /// `foreach (var x in collection) { body }`
    ForEach {
        var: String,
        collection: CSharpExpr,
        body: Vec<Self>,
    },
    /// `try { body } catch (T e) { handlers } finally { finally_ }`
    TryCatch {
        body: Vec<Self>,
        handlers: Vec<CatchClause>,
        finally: Vec<Self>,
    },
    /// `throw expr;`
    Throw(CSharpExpr),
    /// Local variable declaration: `T x = expr;`
    LocalDecl {
        name: String,
        type_name: String,
        init: Option<CSharpExpr>,
    },
    /// Block.
    Block(Vec<Self>),
    /// Comment placeholder.
    Comment(String),
}

/// A catch clause: `catch (ExType Name)`.
#[derive(Debug, Clone, PartialEq)]
pub struct CatchClause {
    pub exception_type: String,
    pub variable: String,
    pub body: Vec<CSharpStmt>,
}

impl fmt::Display for CSharpStmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Assign { target, value } => writeln!(f, "{target} = {value};"),
            Self::Expr(e) => writeln!(f, "{e};"),
            Self::Return(None) => writeln!(f, "return;"),
            Self::Return(Some(e)) => writeln!(f, "return {e};"),
            Self::Throw(e) => writeln!(f, "throw {e};"),
            Self::Comment(s) => writeln!(f, "// {s}"),
            Self::LocalDecl {
                name,
                type_name,
                init: Some(i),
            } => writeln!(f, "{type_name} {name} = {i};"),
            Self::LocalDecl {
                name,
                type_name,
                init: None,
            } => writeln!(f, "{type_name} {name};"),
            Self::FieldAssign { target, value } => writeln!(f, "{target} = {value};"),
            _ => writeln!(f, "/* stmt */"),
        }
    }
}

// ── TypePrinter ───────────────────────────────────────────────────────────────

/// Resolves metadata tokens to C# type names.
#[derive(Debug, Default)]
pub struct TypePrinter {
    table: HashMap<u32, String>,
}

impl TypePrinter {
    /// Create a new printer with a pre-populated type table.
    #[must_use]
    pub const fn new(table: HashMap<u32, String>) -> Self {
        Self { table }
    }

    /// Register a token → type-name mapping.
    pub fn register(&mut self, token: u32, name: String) {
        self.table.insert(token, name);
    }

    /// Resolve a token to a type name.
    ///
    /// Falls back to `"T_0x{token:08x}"` for unknown tokens.
    #[must_use]
    pub fn resolve(&self, token: u32) -> String {
        self.table
            .get(&token)
            .cloned()
            .unwrap_or_else(|| format!("T_0x{token:08x}"))
    }

    /// Return the full type-name table.
    #[must_use]
    pub const fn table(&self) -> &HashMap<u32, String> {
        &self.table
    }
}

// ── ExpressionBuilder ─────────────────────────────────────────────────────────

/// Builds C# expression trees from the CIL evaluation stack.
pub struct ExpressionBuilder {
    stack: Vec<CSharpExpr>,
    local_names: Vec<String>,
    arg_names: Vec<String>,
    pub type_printer: TypePrinter,
}

impl ExpressionBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new(local_count: usize, arg_count: usize, type_printer: TypePrinter) -> Self {
        let local_names = (0..local_count).map(|i| format!("V_{i}")).collect();
        let arg_names = (0..arg_count)
            .map(|i| {
                if i == 0 {
                    "this".to_string()
                } else {
                    format!("arg{i}")
                }
            })
            .collect();
        Self {
            stack: Vec::new(),
            local_names,
            arg_names,
            type_printer,
        }
    }

    /// Push an expression.
    pub fn push(&mut self, expr: CSharpExpr) {
        self.stack.push(expr);
    }

    /// Pop an expression.
    /// # Errors
    ///
    /// Returns [`DecompileError::StackUnderflow`] if the expression stack is
    /// empty, naming `op` as the instruction that asked for the operand.
    pub fn pop(&mut self, op: &str) -> Result<CSharpExpr, DecompileError> {
        self.stack
            .pop()
            .ok_or_else(|| DecompileError::StackUnderflow { op: op.to_string() })
    }

    /// Current stack depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.stack.len()
    }

    /// Local variable name.
    #[must_use]
    pub fn local_name(&self, idx: usize) -> String {
        self.local_names
            .get(idx)
            .cloned()
            .unwrap_or_else(|| format!("V_{idx}"))
    }

    /// Argument name.
    #[must_use]
    pub fn arg_name(&self, idx: usize) -> String {
        self.arg_names
            .get(idx)
            .cloned()
            .unwrap_or_else(|| format!("arg{idx}"))
    }

    /// Process a single CIL instruction and update the expression stack.
    /// # Errors
    ///
    /// Propagates any [`DecompileError`] raised while popping the operands the
    /// instruction consumes.
    pub fn process(&mut self, instr: &CilInstr) -> Result<Option<CSharpStmt>, DecompileError> {
        match instr.mnemonic.as_str() {
            "ldnull" => {
                self.push(CSharpExpr::Null);
                Ok(None)
            }
            "ldc.i4.0" => {
                self.push(CSharpExpr::IntLit(0));
                Ok(None)
            }
            "ldc.i4.1" => {
                self.push(CSharpExpr::IntLit(1));
                Ok(None)
            }
            "ldc.i4.2" => {
                self.push(CSharpExpr::IntLit(2));
                Ok(None)
            }
            "ldc.i4.3" => {
                self.push(CSharpExpr::IntLit(3));
                Ok(None)
            }
            "ldc.i4.4" => {
                self.push(CSharpExpr::IntLit(4));
                Ok(None)
            }
            "ldc.i4.5" => {
                self.push(CSharpExpr::IntLit(5));
                Ok(None)
            }
            "ldc.i4.6" => {
                self.push(CSharpExpr::IntLit(6));
                Ok(None)
            }
            "ldc.i4.7" => {
                self.push(CSharpExpr::IntLit(7));
                Ok(None)
            }
            "ldc.i4.8" => {
                self.push(CSharpExpr::IntLit(8));
                Ok(None)
            }
            "ldc.i4.m1" => {
                self.push(CSharpExpr::IntLit(-1));
                Ok(None)
            }
            "ldc.i4.s" | "ldc.i4" | "ldc.i8" => {
                let v = instr.operands.trim().parse::<i64>().unwrap_or(0);
                self.push(CSharpExpr::IntLit(v));
                Ok(None)
            }
            "ldarg.0" => {
                self.push(CSharpExpr::Arg(self.arg_name(0)));
                Ok(None)
            }
            "ldarg.1" => {
                self.push(CSharpExpr::Arg(self.arg_name(1)));
                Ok(None)
            }
            "ldarg.2" => {
                self.push(CSharpExpr::Arg(self.arg_name(2)));
                Ok(None)
            }
            "ldarg.3" => {
                self.push(CSharpExpr::Arg(self.arg_name(3)));
                Ok(None)
            }
            "ldarg.s" => {
                let idx = instr.operands.trim().parse::<usize>().unwrap_or(0);
                self.push(CSharpExpr::Arg(self.arg_name(idx)));
                Ok(None)
            }
            "ldloc.0" => {
                self.push(CSharpExpr::Local(self.local_name(0)));
                Ok(None)
            }
            "ldloc.1" => {
                self.push(CSharpExpr::Local(self.local_name(1)));
                Ok(None)
            }
            "ldloc.2" => {
                self.push(CSharpExpr::Local(self.local_name(2)));
                Ok(None)
            }
            "ldloc.3" => {
                self.push(CSharpExpr::Local(self.local_name(3)));
                Ok(None)
            }
            "ldloc.s" | "ldloc" => {
                let idx = instr.operands.trim().parse::<usize>().unwrap_or(0);
                self.push(CSharpExpr::Local(self.local_name(idx)));
                Ok(None)
            }
            "stloc.0" => {
                let v = self.pop("stloc.0")?;
                Ok(Some(CSharpStmt::Assign {
                    target: self.local_name(0),
                    value: v,
                }))
            }
            "stloc.1" => {
                let v = self.pop("stloc.1")?;
                Ok(Some(CSharpStmt::Assign {
                    target: self.local_name(1),
                    value: v,
                }))
            }
            "stloc.2" => {
                let v = self.pop("stloc.2")?;
                Ok(Some(CSharpStmt::Assign {
                    target: self.local_name(2),
                    value: v,
                }))
            }
            "stloc.3" => {
                let v = self.pop("stloc.3")?;
                Ok(Some(CSharpStmt::Assign {
                    target: self.local_name(3),
                    value: v,
                }))
            }
            "stloc.s" | "stloc" => {
                let idx = instr.operands.trim().parse::<usize>().unwrap_or(0);
                let v = self.pop("stloc.s")?;
                Ok(Some(CSharpStmt::Assign {
                    target: self.local_name(idx),
                    value: v,
                }))
            }
            "dup" => {
                let top =
                    self.stack
                        .last()
                        .cloned()
                        .ok_or_else(|| DecompileError::StackUnderflow {
                            op: "dup".to_string(),
                        })?;
                self.push(top);
                Ok(None)
            }
            "pop" => {
                let _ = self.pop("pop")?;
                Ok(None)
            }
            "add" | "add.ovf" | "add.ovf.un" => {
                let rhs = self.pop("add")?;
                let lhs = self.pop("add")?;
                self.push(CSharpExpr::BinOp {
                    op: BinOpKind::Add,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                });
                Ok(None)
            }
            "sub" | "sub.ovf" => {
                let rhs = self.pop("sub")?;
                let lhs = self.pop("sub")?;
                self.push(CSharpExpr::BinOp {
                    op: BinOpKind::Sub,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                });
                Ok(None)
            }
            "mul" | "mul.ovf" => {
                let rhs = self.pop("mul")?;
                let lhs = self.pop("mul")?;
                self.push(CSharpExpr::BinOp {
                    op: BinOpKind::Mul,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                });
                Ok(None)
            }
            "div" | "div.un" => {
                let rhs = self.pop("div")?;
                let lhs = self.pop("div")?;
                self.push(CSharpExpr::BinOp {
                    op: BinOpKind::Div,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                });
                Ok(None)
            }
            "rem" | "rem.un" => {
                let rhs = self.pop("rem")?;
                let lhs = self.pop("rem")?;
                self.push(CSharpExpr::BinOp {
                    op: BinOpKind::Rem,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                });
                Ok(None)
            }
            "and" => {
                let rhs = self.pop("and")?;
                let lhs = self.pop("and")?;
                self.push(CSharpExpr::BinOp {
                    op: BinOpKind::And,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                });
                Ok(None)
            }
            "or" => {
                let rhs = self.pop("or")?;
                let lhs = self.pop("or")?;
                self.push(CSharpExpr::BinOp {
                    op: BinOpKind::Or,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                });
                Ok(None)
            }
            "xor" => {
                let rhs = self.pop("xor")?;
                let lhs = self.pop("xor")?;
                self.push(CSharpExpr::BinOp {
                    op: BinOpKind::Xor,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                });
                Ok(None)
            }
            "neg" => {
                let e = self.pop("neg")?;
                self.push(CSharpExpr::UnaryOp {
                    op: UnaryOpKind::Neg,
                    expr: Box::new(e),
                });
                Ok(None)
            }
            "not" => {
                let e = self.pop("not")?;
                self.push(CSharpExpr::UnaryOp {
                    op: UnaryOpKind::Not,
                    expr: Box::new(e),
                });
                Ok(None)
            }
            "ceq" => {
                let rhs = self.pop("ceq")?;
                let lhs = self.pop("ceq")?;
                self.push(CSharpExpr::BinOp {
                    op: BinOpKind::Eq,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                });
                Ok(None)
            }
            "cgt" | "cgt.un" => {
                let rhs = self.pop("cgt")?;
                let lhs = self.pop("cgt")?;
                self.push(CSharpExpr::BinOp {
                    op: BinOpKind::Gt,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                });
                Ok(None)
            }
            "clt" | "clt.un" => {
                let rhs = self.pop("clt")?;
                let lhs = self.pop("clt")?;
                self.push(CSharpExpr::BinOp {
                    op: BinOpKind::Lt,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                });
                Ok(None)
            }
            "ret" => {
                if self.stack.is_empty() {
                    Ok(Some(CSharpStmt::Return(None)))
                } else {
                    let v = self.pop("ret")?;
                    Ok(Some(CSharpStmt::Return(Some(v))))
                }
            }
            "throw" => {
                let e = self.pop("throw")?;
                Ok(Some(CSharpStmt::Throw(e)))
            }
            "call" => {
                // Simplified: use token as method reference
                let token = instr.operands.trim_start_matches('#');
                let expr = CSharpExpr::StaticCall {
                    type_name: "Type".to_string(),
                    method: format!("Method_{token}"),
                    args: Vec::new(),
                };
                self.push(expr);
                Ok(None)
            }
            "newobj" => {
                let token_str = instr.operands.trim_start_matches('#');
                let token = u32::from_str_radix(token_str, 16).unwrap_or(0);
                let type_name = self.type_printer.resolve(token);
                let expr = CSharpExpr::NewObj {
                    type_name,
                    args: Vec::new(),
                };
                self.push(expr);
                Ok(None)
            }
            "ldstr" => {
                let s = instr.operands.clone();
                self.push(CSharpExpr::StringLit(s));
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}

// ── StatementBuilder ──────────────────────────────────────────────────────────

/// Builds a list of C# statements by iterating over CIL instructions.
pub struct StatementBuilder {
    pub stmts: Vec<CSharpStmt>,
    pub expr_builder: ExpressionBuilder,
}

impl StatementBuilder {
    /// Create a new statement builder.
    #[must_use]
    pub const fn new(expr_builder: ExpressionBuilder) -> Self {
        Self {
            stmts: Vec::new(),
            expr_builder,
        }
    }

    /// Process all instructions in a method body.
    /// # Errors
    ///
    /// Propagates the first [`DecompileError`] raised by any instruction.
    pub fn process_all(&mut self, instrs: &[CilInstr]) -> Result<(), DecompileError> {
        for instr in instrs {
            if let Some(stmt) = self.expr_builder.process(instr)? {
                self.stmts.push(stmt);
            }
        }
        Ok(())
    }

    /// Return the accumulated statements.
    #[must_use]
    pub fn statements(&self) -> &[CSharpStmt] {
        &self.stmts
    }
}

// ── MethodDecompiler ──────────────────────────────────────────────────────────

/// Decompiles a single CIL method body into a [`DecompiledMethod`].
pub struct MethodDecompiler {
    pub type_printer: TypePrinter,
    pub local_count: usize,
    pub arg_count: usize,
}

impl MethodDecompiler {
    /// Create a new method decompiler.
    #[must_use]
    pub const fn new(type_printer: TypePrinter, local_count: usize, arg_count: usize) -> Self {
        Self {
            type_printer,
            local_count,
            arg_count,
        }
    }

    /// Decompile raw CIL bytes into a [`DecompiledMethod`].
    ///
    /// # Errors
    ///
    /// Returns [`DecompileError`] if decoding or decompilation fails.
    pub fn decompile(&self, bytes: &[u8]) -> Result<DecompiledMethod, DecompileError> {
        if bytes.is_empty() {
            return Err(DecompileError::EmptyMethod);
        }
        // Decode CIL instructions
        let instrs = decode_cil_bytes(bytes)?;

        // Check for async pattern
        let is_async = AsyncMethodRecovery::detect(&instrs);
        let is_linq = LinqRecovery::detect(&instrs);

        let printer = TypePrinter::new(self.type_printer.table().clone());
        let eb = ExpressionBuilder::new(self.local_count, self.arg_count, printer);
        let mut sb = StatementBuilder::new(eb);
        sb.process_all(&instrs)?;

        Ok(DecompiledMethod {
            stmts: sb.stmts,
            is_async,
            is_linq,
            instruction_count: instrs.len(),
        })
    }
}

/// Result of decompiling a CIL method body.
#[derive(Debug, Clone)]
pub struct DecompiledMethod {
    pub stmts: Vec<CSharpStmt>,
    pub is_async: bool,
    pub is_linq: bool,
    pub instruction_count: usize,
}

// ── CSharpCodeGenerator ───────────────────────────────────────────────────────

/// Generates formatted C# source code from a [`DecompiledMethod`].
pub struct CSharpCodeGenerator {
    indent_width: usize,
    current_indent: usize,
}

impl CSharpCodeGenerator {
    #[must_use]
    pub const fn new(indent_width: usize) -> Self {
        Self {
            indent_width,
            current_indent: 0,
        }
    }

    fn indent_str(&self) -> String {
        " ".repeat(self.current_indent)
    }

    const fn push_indent(&mut self) {
        self.current_indent += self.indent_width;
    }
    const fn pop_indent(&mut self) {
        self.current_indent = self.current_indent.saturating_sub(self.indent_width);
    }

    /// Generate a C# method from a [`DecompiledMethod`].
    #[must_use]
    pub fn generate_method(
        &mut self,
        method: &DecompiledMethod,
        name: &str,
        return_type: &str,
    ) -> String {
        let mut code = String::new();
        if method.is_async {
            writeln!(code,
                "{}async {} {}()",
                self.indent_str(),
                return_type,
                name
            )
                .expect("writing to a String is infallible");
        } else {
            writeln!(code,
                "{}{} {}()",
                self.indent_str(),
                return_type,
                name
            )
                .expect("writing to a String is infallible");
        }
        writeln!(code, "{}{{", self.indent_str()).expect("writing to a String is infallible");
        self.push_indent();
        for stmt in &method.stmts {
            write!(code, "{}{}", self.indent_str(), stmt).expect("writing to a String is infallible");
        }
        self.pop_indent();
        writeln!(code, "{}}}", self.indent_str()).expect("writing to a String is infallible");
        code
    }

    /// Generate just the method body (without signature).
    #[must_use]
    pub fn generate_body(&mut self, method: &DecompiledMethod) -> String {
        let mut code = String::new();
        self.push_indent();
        for stmt in &method.stmts {
            write!(code, "{}{}", self.indent_str(), stmt).expect("writing to a String is infallible");
        }
        self.pop_indent();
        code
    }
}

impl Default for CSharpCodeGenerator {
    fn default() -> Self {
        Self::new(4)
    }
}

// ── CilStackSimulator ─────────────────────────────────────────────────────────

/// Simulates the CIL evaluation stack for type analysis.
#[derive(Debug, Clone, Default)]
pub struct CilStackSimulator {
    stack: Vec<CilStackEntry>,
    max_depth: usize,
}

/// A single entry on the simulated CIL evaluation stack.
#[derive(Debug, Clone)]
pub struct CilStackEntry {
    /// Approximate type category.
    pub type_category: CilTypeCategory,
    /// Source instruction mnemonic.
    pub source: String,
}

/// Broad category for a CIL stack value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CilTypeCategory {
    Int32,
    Int64,
    NativeInt,
    Float,
    Object,
    ManagedPointer,
    Unknown,
}

impl CilTypeCategory {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Int32 => "int32",
            Self::Int64 => "int64",
            Self::NativeInt => "native_int",
            Self::Float => "float",
            Self::Object => "object",
            Self::ManagedPointer => "ref",
            Self::Unknown => "?",
        }
    }
}

impl CilStackSimulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push an entry.
    pub fn push(&mut self, cat: CilTypeCategory, source: &str) {
        self.stack.push(CilStackEntry {
            type_category: cat,
            source: source.to_string(),
        });
        self.max_depth = self.max_depth.max(self.stack.len());
    }

    /// Pop an entry.
    pub fn pop(&mut self) -> Option<CilStackEntry> {
        self.stack.pop()
    }

    /// Current depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.stack.len()
    }

    /// Maximum stack depth seen.
    #[must_use]
    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Simulate an instruction.
    pub fn simulate(&mut self, mnemonic: &str) {
        match mnemonic {
            "ldc.i4" | "ldc.i4.0" | "ldc.i4.1" | "ldc.i4.m1" | "ldc.i4.s" | "ldc.i4.2"
            | "ldc.i4.3" | "ldc.i4.4" | "ldc.i4.5" | "ldc.i4.6" | "ldc.i4.7" | "ldc.i4.8" => {
                self.push(CilTypeCategory::Int32, mnemonic);
            }
            "ldc.i8" => {
                self.push(CilTypeCategory::Int64, mnemonic);
            }
            "ldc.r4" | "ldc.r8" => {
                self.push(CilTypeCategory::Float, mnemonic);
            }
            "ldarg.0" | "ldarg.1" | "ldarg.2" | "ldarg.3" | "ldarg.s" | "ldarg" | "ldloc.0"
            | "ldloc.1" | "ldloc.2" | "ldloc.3" | "ldloc.s" | "ldloc" => {
                self.push(CilTypeCategory::Unknown, mnemonic);
            }
            "ldnull" | "ldstr" | "newobj" | "newarr" => {
                self.push(CilTypeCategory::Object, mnemonic);
            }
            "add" | "sub" | "mul" | "div" | "rem" | "and" | "or" | "xor" | "neg" | "not"
            | "shl" | "shr" | "shr.un" => {
                let _ = self.pop();
                let _ = self.pop();
                self.push(CilTypeCategory::Unknown, mnemonic);
            }
            "ceq" | "cgt" | "clt" | "cgt.un" | "clt.un" => {
                let _ = self.pop();
                let _ = self.pop();
                self.push(CilTypeCategory::Int32, mnemonic);
            }
            "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc.s" | "stloc" | "starg.s"
            | "starg" | "pop" => {
                let _ = self.pop();
            }
            "dup" => {
                let top = self.stack.last().cloned();
                if let Some(e) = top {
                    self.push(e.type_category, &e.source);
                }
            }
            _ => {}
        }
    }
}

impl DecompiledMethod {
    /// Pretty-print the method body.
    #[must_use]
    pub fn pretty_print(&self) -> String {
        let mut s = String::new();
        if self.is_async {
            s.push_str("// [async state machine]\n");
        }
        if self.is_linq {
            s.push_str("// [LINQ query pattern]\n");
        }
        for stmt in &self.stmts {
            write!(s, "{stmt}").expect("writing to a String is infallible");
        }
        s
    }
}

// ── AsyncMethodRecovery ───────────────────────────────────────────────────────

/// Detects and marks C# async method (state-machine) patterns.
pub struct AsyncMethodRecovery;

impl AsyncMethodRecovery {
    /// Return `true` if the instruction stream exhibits async state-machine patterns.
    ///
    /// Heuristics: presence of `callvirt` to `GetAwaiter`, `IsCompleted`, or
    /// `GetResult` methods, or `newobj` of a compiler-generated `<>d__` type.
    #[must_use]
    pub fn detect(instrs: &[CilInstr]) -> bool {
        for i in instrs {
            let ops = &i.operands;
            if (i.mnemonic == "callvirt" || i.mnemonic == "call")
                && (ops.contains("GetAwaiter")
                    || ops.contains("GetResult")
                    || ops.contains("IsCompleted"))
            {
                return true;
            }
            if i.mnemonic == "newobj" && (ops.contains("d__") || ops.contains("stateMachine")) {
                return true;
            }
        }
        false
    }

    /// Wrap a list of statements in an `await`-form if async pattern is detected.
    #[must_use]
    pub fn recover(stmts: Vec<CSharpStmt>) -> Vec<CSharpStmt> {
        stmts
            .into_iter()
            .map(|s| match s {
                CSharpStmt::Expr(CSharpExpr::Call { obj, method, args })
                    if method.contains("GetResult") =>
                {
                    let inner = CSharpExpr::Call { obj, method, args };
                    CSharpStmt::Expr(CSharpExpr::Await(Box::new(inner)))
                }
                other => other,
            })
            .collect()
    }
}

// ── LinqRecovery ──────────────────────────────────────────────────────────────

/// Detects and recovers LINQ query patterns.
pub struct LinqRecovery;

impl LinqRecovery {
    /// Detect LINQ pattern: calls to `Where`, `Select`, `OrderBy`, etc. on Enumerable.
    #[must_use]
    pub fn detect(instrs: &[CilInstr]) -> bool {
        let linq_methods = [
            "Where",
            "Select",
            "OrderBy",
            "GroupBy",
            "First",
            "FirstOrDefault",
            "ToList",
            "ToArray",
            "Any",
            "All",
        ];
        for i in instrs {
            let ops = &i.operands;
            for m in &linq_methods {
                if ops.contains(m) {
                    return true;
                }
            }
        }
        false
    }

    /// Build a LINQ expression string from a fluent chain.
    #[must_use]
    pub fn build_query(source: &str, operations: &[(&str, &str)]) -> CSharpExpr {
        let mut parts = vec![source.to_string()];
        for (method, arg) in operations {
            parts.push(format!(".{method}({arg})"));
        }
        CSharpExpr::LinqQuery(parts.join(""))
    }
}

// ── CilDecompiler — top-level entry ──────────────────────────────────────────

/// Top-level CIL decompiler that combines all passes.
pub struct CilDecompiler {
    pub type_printer: TypePrinter,
}

impl CilDecompiler {
    /// Create a new decompiler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            type_printer: TypePrinter::default(),
        }
    }

    /// Register a type name for a metadata token.
    pub fn register_type(&mut self, token: u32, name: String) {
        self.type_printer.register(token, name);
    }

    /// Decompile a method with the given number of locals and arguments.
    ///
    /// # Errors
    ///
    /// Propagates any [`DecompileError`] raised while decoding the byte stream
    /// or while rebuilding expressions from it.
    pub fn decompile_method(
        &self,
        bytes: &[u8],
        local_count: usize,
        arg_count: usize,
    ) -> Result<DecompiledMethod, DecompileError> {
        let printer = TypePrinter::new(self.type_printer.table().clone());
        let md = MethodDecompiler::new(printer, local_count, arg_count);
        md.decompile(bytes)
    }
}

impl Default for CilDecompiler {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Decode a sequence of CIL instructions from a byte slice.
/// # Errors
///
/// Returns [`DecompileError`] if the byte stream contains an instruction that
/// cannot be decoded.
pub fn decode_cil_bytes(bytes: &[u8]) -> Result<Vec<CilInstr>, DecompileError> {
    // CIL instructions average ~2 bytes; preallocate to cut reallocations.
    let mut instrs = Vec::with_capacity(bytes.len() / 2);
    let mut pos = 0;
    while pos < bytes.len() {
        match CilInstr::decode(&bytes[pos..]) {
            Ok((instr, n)) => {
                pos += n;
                instrs.push(instr);
            }
            Err(CilDecodeError::Truncated) => break,
            Err(e) => return Err(DecompileError::UnsupportedOpcode(e.to_string())),
        }
    }
    Ok(instrs)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_printer() -> TypePrinter {
        let mut p = TypePrinter::default();
        p.register(0x0200_0001, "System.String".to_string());
        p
    }

    // --- DecompileError ---

    #[test]
    fn test_error_display_empty() {
        let e = DecompileError::EmptyMethod;
        assert!(e.to_string().contains("empty"));
    }

    #[test]
    fn test_error_stack_underflow() {
        let e = DecompileError::StackUnderflow {
            op: "add".to_string(),
        };
        assert!(e.to_string().contains("add"));
    }

    // --- CSharpExpr ---

    #[test]
    fn test_int_lit_display() {
        let e = CSharpExpr::IntLit(42);
        assert_eq!(e.to_string(), "42");
    }

    #[test]
    fn test_null_display() {
        assert_eq!(CSharpExpr::Null.to_string(), "null");
    }

    #[test]
    fn test_binop_add_display() {
        let e = CSharpExpr::BinOp {
            op: BinOpKind::Add,
            lhs: Box::new(CSharpExpr::IntLit(1)),
            rhs: Box::new(CSharpExpr::IntLit(2)),
        };
        assert_eq!(e.to_string(), "(1 + 2)");
    }

    #[test]
    fn test_cast_display() {
        let e = CSharpExpr::Cast {
            target_type: "int".to_string(),
            expr: Box::new(CSharpExpr::Local("x".to_string())),
        };
        assert!(e.to_string().contains("int"));
    }

    #[test]
    fn test_await_display() {
        let e = CSharpExpr::Await(Box::new(CSharpExpr::Null));
        assert!(e.to_string().starts_with("await"));
    }

    #[test]
    fn test_linq_query_display() {
        let e = CSharpExpr::LinqQuery("source.Where(x => x > 0)".to_string());
        assert!(e.to_string().contains("Where"));
    }

    #[test]
    fn test_new_obj_display() {
        let e = CSharpExpr::NewObj {
            type_name: "Foo".to_string(),
            args: vec![],
        };
        assert!(e.to_string().starts_with("new Foo"));
    }

    #[test]
    fn test_new_array_display() {
        let e = CSharpExpr::NewArray {
            elem_type: "int".to_string(),
            length: Box::new(CSharpExpr::IntLit(10)),
        };
        assert!(e.to_string().contains("int"));
    }

    // --- TypePrinter ---

    #[test]
    fn test_type_printer_resolve_known() {
        let p = make_printer();
        assert_eq!(p.resolve(0x0200_0001), "System.String");
    }

    #[test]
    fn test_type_printer_resolve_unknown() {
        let p = make_printer();
        let s = p.resolve(0xFFFF_FFFF);
        assert!(s.starts_with("T_0x"));
    }

    #[test]
    fn test_type_printer_register_and_resolve() {
        let mut p = TypePrinter::default();
        p.register(42, "MyType".to_string());
        assert_eq!(p.resolve(42), "MyType");
    }

    // --- ExpressionBuilder ---

    #[test]
    fn test_expr_builder_push_pop() {
        let mut eb = ExpressionBuilder::new(4, 2, TypePrinter::default());
        eb.push(CSharpExpr::IntLit(7));
        assert_eq!(eb.depth(), 1);
        let e = eb.pop("test").unwrap();
        assert_eq!(e, CSharpExpr::IntLit(7));
    }

    #[test]
    fn test_expr_builder_pop_underflow() {
        let mut eb = ExpressionBuilder::new(0, 0, TypePrinter::default());
        assert!(eb.pop("op").is_err());
    }

    #[test]
    fn test_expr_builder_local_name() {
        let eb = ExpressionBuilder::new(4, 0, TypePrinter::default());
        assert_eq!(eb.local_name(0), "V_0");
        assert_eq!(eb.local_name(3), "V_3");
    }

    #[test]
    fn test_expr_builder_arg_name() {
        let eb = ExpressionBuilder::new(0, 3, TypePrinter::default());
        assert_eq!(eb.arg_name(0), "this");
        assert_eq!(eb.arg_name(1), "arg1");
    }

    #[test]
    fn test_expr_builder_process_ldc_i4_0() {
        let mut eb = ExpressionBuilder::new(0, 0, TypePrinter::default());
        let instr = CilInstr {
            raw: vec![0x16],
            mnemonic: "ldc.i4.0".to_string(),
            operands: String::new(),
            flags: rustre_core::arch::InstrFlags::NONE,
        };
        eb.process(&instr).unwrap();
        assert_eq!(eb.stack[0], CSharpExpr::IntLit(0));
    }

    #[test]
    fn test_expr_builder_process_add() {
        let mut eb = ExpressionBuilder::new(0, 0, TypePrinter::default());
        eb.push(CSharpExpr::IntLit(3));
        eb.push(CSharpExpr::IntLit(5));
        let instr = CilInstr {
            raw: vec![0x58],
            mnemonic: "add".to_string(),
            operands: String::new(),
            flags: rustre_core::arch::InstrFlags::NONE,
        };
        eb.process(&instr).unwrap();
        assert_eq!(eb.depth(), 1);
        match &eb.stack[0] {
            CSharpExpr::BinOp {
                op: BinOpKind::Add, ..
            } => {}
            other => panic!("expected BinOp::Add, got {other:?}"),
        }
    }

    #[test]
    fn test_expr_builder_process_ret_void() {
        let mut eb = ExpressionBuilder::new(0, 0, TypePrinter::default());
        let instr = CilInstr {
            raw: vec![0x2a],
            mnemonic: "ret".to_string(),
            operands: String::new(),
            flags: rustre_core::arch::InstrFlags::RET,
        };
        let s = eb.process(&instr).unwrap();
        assert!(matches!(s, Some(CSharpStmt::Return(None))));
    }

    #[test]
    fn test_expr_builder_process_ret_value() {
        let mut eb = ExpressionBuilder::new(0, 0, TypePrinter::default());
        eb.push(CSharpExpr::IntLit(1));
        let instr = CilInstr {
            raw: vec![0x2a],
            mnemonic: "ret".to_string(),
            operands: String::new(),
            flags: rustre_core::arch::InstrFlags::RET,
        };
        let s = eb.process(&instr).unwrap();
        assert!(matches!(s, Some(CSharpStmt::Return(Some(_)))));
    }

    // --- MethodDecompiler ---

    #[test]
    fn test_method_decompile_empty_error() {
        let md = MethodDecompiler::new(TypePrinter::default(), 0, 0);
        assert!(md.decompile(&[]).is_err());
    }

    #[test]
    fn test_method_decompile_nop_ret() {
        let md = MethodDecompiler::new(TypePrinter::default(), 0, 0);
        let bytes = [0x00u8, 0x2a]; // nop, ret
        let result = md.decompile(&bytes).unwrap();
        assert_eq!(result.instruction_count, 2);
    }

    #[test]
    fn test_method_decompile_is_not_async() {
        let md = MethodDecompiler::new(TypePrinter::default(), 1, 1);
        let bytes = [0x02u8, 0x2a]; // ldarg.0, ret
        let result = md.decompile(&bytes).unwrap();
        assert!(!result.is_async);
    }

    #[test]
    fn test_method_decompile_pretty_print() {
        let md = MethodDecompiler::new(TypePrinter::default(), 1, 0);
        let bytes = [0x17u8, 0x0a, 0x2a]; // ldc.i4.1, stloc.0, ret
        let result = md.decompile(&bytes).unwrap();
        let pp = result.pretty_print();
        assert!(!pp.is_empty());
    }

    // --- AsyncMethodRecovery ---

    #[test]
    fn test_async_detect_false_on_empty() {
        assert!(!AsyncMethodRecovery::detect(&[]));
    }

    #[test]
    fn test_async_recover_passthrough() {
        let stmts = vec![CSharpStmt::Comment("test".to_string())];
        let r = AsyncMethodRecovery::recover(stmts);
        assert_eq!(r.len(), 1);
    }

    // --- LinqRecovery ---

    #[test]
    fn test_linq_detect_false_on_empty() {
        assert!(!LinqRecovery::detect(&[]));
    }

    #[test]
    fn test_linq_build_query() {
        let e = LinqRecovery::build_query("items", &[("Where", "x => x > 0"), ("ToList", "")]);
        match e {
            CSharpExpr::LinqQuery(s) => {
                assert!(s.contains("items"));
                assert!(s.contains("Where"));
            }
            _ => panic!("expected LinqQuery"),
        }
    }

    // --- CilDecompiler ---

    #[test]
    fn test_cil_decompiler_new() {
        let d = CilDecompiler::new();
        assert!(d.type_printer.table().is_empty());
    }

    #[test]
    fn test_cil_decompiler_register_type() {
        let mut d = CilDecompiler::new();
        d.register_type(1, "int".to_string());
        assert_eq!(d.type_printer.resolve(1), "int");
    }

    #[test]
    fn test_cil_decompile_method_simple() {
        let d = CilDecompiler::new();
        let bytes = [0x00u8, 0x2a]; // nop, ret
        let result = d.decompile_method(&bytes, 0, 0).unwrap();
        assert_eq!(result.instruction_count, 2);
    }

    #[test]
    fn test_decode_cil_bytes_nop() {
        let instrs = decode_cil_bytes(&[0x00]).unwrap();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].mnemonic, "nop");
    }

    #[test]
    fn test_decode_cil_bytes_truncated_ignored() {
        let instrs = decode_cil_bytes(&[0x38, 0x00]).unwrap(); // partial br
        // truncated — depends on length check; may produce 0 or error
        let _ = instrs;
    }

    // --- Additional BinOpKind display tests ---

    #[test]
    fn test_binop_sub_display() {
        assert_eq!(format!("{}", BinOpKind::Sub), "-");
    }

    #[test]
    fn test_binop_mul_display() {
        assert_eq!(format!("{}", BinOpKind::Mul), "*");
    }

    #[test]
    fn test_binop_div_display() {
        assert_eq!(format!("{}", BinOpKind::Div), "/");
    }

    #[test]
    fn test_binop_ne_display() {
        assert_eq!(format!("{}", BinOpKind::Ne), "!=");
    }

    #[test]
    fn test_unary_neg_display() {
        assert_eq!(format!("{}", UnaryOpKind::Neg), "-");
    }

    #[test]
    fn test_unary_not_display() {
        assert_eq!(format!("{}", UnaryOpKind::Not), "!");
    }

    // --- Additional ExpressionBuilder tests ---

    #[test]
    fn test_expr_builder_ldloc_0() {
        let mut eb = ExpressionBuilder::new(4, 0, TypePrinter::default());
        let instr = CilInstr {
            raw: vec![0x06],
            mnemonic: "ldloc.0".to_string(),
            operands: String::new(),
            flags: rustre_core::arch::InstrFlags::NONE,
        };
        eb.process(&instr).unwrap();
        assert_eq!(eb.depth(), 1);
        match &eb.stack[0] {
            CSharpExpr::Local(n) => assert_eq!(n, "V_0"),
            _ => panic!("expected Local"),
        }
    }

    #[test]
    fn test_expr_builder_dup() {
        let mut eb = ExpressionBuilder::new(0, 0, TypePrinter::default());
        eb.push(CSharpExpr::IntLit(42));
        let instr = CilInstr {
            raw: vec![0x25],
            mnemonic: "dup".to_string(),
            operands: String::new(),
            flags: rustre_core::arch::InstrFlags::NONE,
        };
        eb.process(&instr).unwrap();
        assert_eq!(eb.depth(), 2);
    }

    #[test]
    fn test_expr_builder_pop() {
        let mut eb = ExpressionBuilder::new(0, 0, TypePrinter::default());
        eb.push(CSharpExpr::IntLit(1));
        let instr = CilInstr {
            raw: vec![0x26],
            mnemonic: "pop".to_string(),
            operands: String::new(),
            flags: rustre_core::arch::InstrFlags::NONE,
        };
        eb.process(&instr).unwrap();
        assert_eq!(eb.depth(), 0);
    }

    #[test]
    fn test_expr_builder_xor() {
        let mut eb = ExpressionBuilder::new(0, 0, TypePrinter::default());
        eb.push(CSharpExpr::IntLit(0xFF));
        eb.push(CSharpExpr::IntLit(0x0F));
        let instr = CilInstr {
            raw: vec![0x61],
            mnemonic: "xor".to_string(),
            operands: String::new(),
            flags: rustre_core::arch::InstrFlags::NONE,
        };
        eb.process(&instr).unwrap();
        assert!(matches!(
            &eb.stack[0],
            CSharpExpr::BinOp {
                op: BinOpKind::Xor,
                ..
            }
        ));
    }

    #[test]
    fn test_expr_builder_neg() {
        let mut eb = ExpressionBuilder::new(0, 0, TypePrinter::default());
        eb.push(CSharpExpr::IntLit(5));
        let instr = CilInstr {
            raw: vec![0x65],
            mnemonic: "neg".to_string(),
            operands: String::new(),
            flags: rustre_core::arch::InstrFlags::NONE,
        };
        eb.process(&instr).unwrap();
        assert!(matches!(
            &eb.stack[0],
            CSharpExpr::UnaryOp {
                op: UnaryOpKind::Neg,
                ..
            }
        ));
    }

    #[test]
    fn test_expr_builder_ceq() {
        let mut eb = ExpressionBuilder::new(0, 0, TypePrinter::default());
        eb.push(CSharpExpr::IntLit(1));
        eb.push(CSharpExpr::IntLit(1));
        let instr = CilInstr {
            raw: vec![0xfe, 0x01],
            mnemonic: "ceq".to_string(),
            operands: String::new(),
            flags: rustre_core::arch::InstrFlags::NONE,
        };
        eb.process(&instr).unwrap();
        assert!(matches!(
            &eb.stack[0],
            CSharpExpr::BinOp {
                op: BinOpKind::Eq,
                ..
            }
        ));
    }

    // --- CSharpStmt display tests ---

    #[test]
    fn test_stmt_assign_display() {
        let s = CSharpStmt::Assign {
            target: "x".to_string(),
            value: CSharpExpr::IntLit(0),
        };
        assert!(s.to_string().contains('x'));
        assert!(s.to_string().contains('0'));
    }

    #[test]
    fn test_stmt_expr_display() {
        let s = CSharpStmt::Expr(CSharpExpr::Null);
        assert!(s.to_string().contains("null"));
    }

    #[test]
    fn test_stmt_throw_display() {
        let s = CSharpStmt::Throw(CSharpExpr::Null);
        assert!(s.to_string().contains("throw"));
    }

    #[test]
    fn test_stmt_local_decl_display() {
        let s = CSharpStmt::LocalDecl {
            name: "y".to_string(),
            type_name: "int".to_string(),
            init: Some(CSharpExpr::IntLit(5)),
        };
        let d = s.to_string();
        assert!(d.contains("int"));
        assert!(d.contains('y'));
    }

    // --- CSharpExpr variants ---

    #[test]
    fn test_field_access_display() {
        let e = CSharpExpr::Field {
            obj: Box::new(CSharpExpr::Local("obj".to_string())),
            field: "x".to_string(),
        };
        assert_eq!(e.to_string(), "obj.x");
    }

    #[test]
    fn test_array_elem_display() {
        let e = CSharpExpr::ArrayElem {
            arr: Box::new(CSharpExpr::Local("arr".to_string())),
            idx: Box::new(CSharpExpr::IntLit(0)),
        };
        assert!(e.to_string().contains("arr[0]"));
    }

    #[test]
    fn test_is_inst_display() {
        let e = CSharpExpr::IsInst {
            expr: Box::new(CSharpExpr::Null),
            type_name: "string".to_string(),
        };
        assert!(e.to_string().contains("is"));
    }

    #[test]
    fn test_ternary_display() {
        let e = CSharpExpr::Ternary {
            cond: Box::new(CSharpExpr::IntLit(1)),
            then: Box::new(CSharpExpr::IntLit(2)),
            else_: Box::new(CSharpExpr::IntLit(3)),
        };
        assert!(e.to_string().contains('?'));
        assert!(e.to_string().contains(':'));
    }

    #[test]
    fn test_default_display() {
        let e = CSharpExpr::Default("int".to_string());
        assert!(e.to_string().contains("default(int)"));
    }
}
