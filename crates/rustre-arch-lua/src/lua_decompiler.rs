//! `lua_decompiler` — Lua bytecode decompiler producing Lua 5.x-style source.
//!
//! Converts a sequence of Lua VM instructions back to structured Lua AST nodes
//! and formats them as readable source code.
//!
//! # Supported constructs
//! * Expressions: `LuaExpr` — binop, unop, call, index, field, const, func
//! * Statements: `LuaStmt` — assign, if, while, for, repeat, return, local
//! * [`UpvalueResolver`] — resolves upvalue references to source names
//! * [`LuaFormatter`] — formats AST to indented Lua source text
//! * [`LuaDecompiler`] — top-level facade

use std::collections::HashMap;
use std::fmt::{self, Write as FmtWrite};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Lua expressions
// ---------------------------------------------------------------------------

/// A binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Concat,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BAnd,
    BOr,
    BXor,
    Shl,
    Shr,
    IDiv,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::Pow => "^",
            Self::Concat => "..",
            Self::Eq => "==",
            Self::Ne => "~=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::And => "and",
            Self::Or => "or",
            Self::BAnd => "&",
            Self::BOr => "|",
            Self::BXor => "~",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::IDiv => "//",
        };
        write!(f, "{s}")
    }
}

/// A unary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnOp {
    Neg,
    Not,
    Len,
    BNot,
}

impl fmt::Display for UnOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Neg => "-",
            Self::Not => "not ",
            Self::Len => "#",
            Self::BNot => "~",
        };
        write!(f, "{s}")
    }
}

/// A Lua constant value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LuaConst {
    Nil,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

impl fmt::Display for LuaConst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "{s:?}"),
        }
    }
}

/// A Lua expression node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LuaExpr {
    /// A constant literal.
    Const(LuaConst),
    /// A named variable.
    Name(String),
    /// Binary operation.
    BinOp {
        op: BinOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// Unary operation.
    UnOp { op: UnOp, operand: Box<Self> },
    /// Function call: `func(args...)`.
    Call {
        func: Box<Self>,
        args: Vec<Self>,
    },
    /// Method call: `obj:method(args...)`.
    MethodCall {
        obj: Box<Self>,
        method: String,
        args: Vec<Self>,
    },
    /// Table index: `table[key]`.
    Index {
        table: Box<Self>,
        key: Box<Self>,
    },
    /// Field access: `table.field`.
    Field { table: Box<Self>, field: String },
    /// Function expression: `function(params) body end`.
    FuncExpr {
        params: Vec<String>,
        body: Vec<LuaStmt>,
        has_vararg: bool,
    },
    /// Table constructor: `{...}`.
    Table(Vec<TableField>),
    /// Upvalue reference.
    Upvalue { index: u8, name: Option<String> },
    /// Vararg `...`.
    Vararg,
}

/// A table constructor field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TableField {
    Keyed { key: LuaExpr, value: LuaExpr },
    Indexed(LuaExpr),
}

// ---------------------------------------------------------------------------
// Lua statements
// ---------------------------------------------------------------------------

/// A Lua statement node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LuaStmt {
    /// Assignment: `targets = values`.
    Assign {
        targets: Vec<LuaExpr>,
        values: Vec<LuaExpr>,
    },
    /// Local declaration: `local names = values`.
    Local {
        names: Vec<String>,
        values: Vec<LuaExpr>,
    },
    /// Call statement.
    Call(LuaExpr),
    /// Do block.
    Do(Vec<Self>),
    /// While loop.
    While { cond: LuaExpr, body: Vec<Self> },
    /// Repeat-until loop.
    Repeat { body: Vec<Self>, until: LuaExpr },
    /// Numeric for: `for i = start, limit [, step] do`.
    NumericFor {
        var: String,
        start: LuaExpr,
        limit: LuaExpr,
        step: Option<LuaExpr>,
        body: Vec<Self>,
    },
    /// Generic for: `for vars in exprs do`.
    GenericFor {
        vars: Vec<String>,
        exprs: Vec<LuaExpr>,
        body: Vec<Self>,
    },
    /// If statement.
    If {
        cond: LuaExpr,
        then_body: Vec<Self>,
        elseif: Vec<(LuaExpr, Vec<Self>)>,
        else_body: Option<Vec<Self>>,
    },
    /// Return statement.
    Return(Vec<LuaExpr>),
    /// Break statement.
    Break,
    /// Goto statement (Lua 5.2+).
    Goto(String),
    /// Label statement.
    Label(String),
    /// Function definition (sugar for assignment).
    FuncDef {
        name: LuaExpr,
        params: Vec<String>,
        body: Vec<Self>,
        has_vararg: bool,
    },
}

// ---------------------------------------------------------------------------
// Decompiled function
// ---------------------------------------------------------------------------

/// A decompiled Lua function prototype.
#[derive(Debug, Clone)]
pub struct DecompileFunction {
    pub name: Option<String>,
    pub params: Vec<String>,
    pub has_vararg: bool,
    pub upvalue_names: Vec<String>,
    pub locals: Vec<String>,
    pub stmts: Vec<LuaStmt>,
    /// Nested function protos.
    pub protos: Vec<Self>,
}

impl DecompileFunction {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            name: None,
            params: Vec::new(),
            has_vararg: false,
            upvalue_names: Vec::new(),
            locals: Vec::new(),
            stmts: Vec::new(),
            protos: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

impl Default for DecompileFunction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// UpvalueResolver
// ---------------------------------------------------------------------------

/// Resolves upvalue indices to their source names.
#[derive(Debug, Default)]
pub struct UpvalueResolver {
    names: HashMap<u8, String>,
}

impl UpvalueResolver {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an upvalue index → name mapping.
    pub fn register(&mut self, index: u8, name: impl Into<String>) {
        self.names.insert(index, name.into());
    }

    /// Resolve an index to its name, or generate a fallback.
    #[must_use] 
    pub fn resolve(&self, index: u8) -> String {
        self.names
            .get(&index)
            .cloned()
            .unwrap_or_else(|| format!("_upval_{index}"))
    }

    /// Apply resolution to an expression tree.
    #[must_use] 
    pub fn resolve_expr(&self, expr: LuaExpr) -> LuaExpr {
        match expr {
            LuaExpr::Upvalue { index, .. } => LuaExpr::Name(self.resolve(index)),
            LuaExpr::BinOp { op, lhs, rhs } => LuaExpr::BinOp {
                op,
                lhs: Box::new(self.resolve_expr(*lhs)),
                rhs: Box::new(self.resolve_expr(*rhs)),
            },
            LuaExpr::UnOp { op, operand } => LuaExpr::UnOp {
                op,
                operand: Box::new(self.resolve_expr(*operand)),
            },
            LuaExpr::Call { func, args } => LuaExpr::Call {
                func: Box::new(self.resolve_expr(*func)),
                args: args.into_iter().map(|a| self.resolve_expr(a)).collect(),
            },
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// LuaFormatter
// ---------------------------------------------------------------------------

/// Formats a Lua AST to a source string.
#[derive(Debug)]
pub struct LuaFormatter {
    indent_str: String,
}

impl Default for LuaFormatter {
    fn default() -> Self {
        Self {
            indent_str: "  ".into(),
        }
    }
}

impl LuaFormatter {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn with_indent(mut self, s: impl Into<String>) -> Self {
        self.indent_str = s.into();
        self
    }

    fn indent(&self, depth: usize) -> String {
        self.indent_str.repeat(depth)
    }

    /// Count all expressions of a given kind in a statement list.
    #[must_use] 
    pub fn count_calls(stmts: &[LuaStmt]) -> usize {
        let mut count = 0;
        for stmt in stmts {
            match stmt {
                LuaStmt::Call(e) => {
                    if matches!(e, LuaExpr::Call { .. } | LuaExpr::MethodCall { .. }) {
                        count += 1;
                    }
                }
                LuaStmt::While { body, .. } | LuaStmt::Do(body) | LuaStmt::Repeat { body, .. } => count += Self::count_calls(body),
                LuaStmt::If {
                    then_body,
                    elseif,
                    else_body,
                    ..
                } => {
                    count += Self::count_calls(then_body);
                    for (_, b) in elseif {
                        count += Self::count_calls(b);
                    }
                    if let Some(eb) = else_body {
                        count += Self::count_calls(eb);
                    }
                }
                LuaStmt::NumericFor { body, .. } | LuaStmt::GenericFor { body, .. } => {
                    count += Self::count_calls(body);
                }
                _ => {}
            }
        }
        count
    }

    #[must_use] 
    pub fn format_expr(&self, expr: &LuaExpr) -> String {
        self.fmt_expr(expr, 0)
    }

    fn fmt_expr(&self, expr: &LuaExpr, _depth: usize) -> String {
        match expr {
            LuaExpr::Const(c) => c.to_string(),
            LuaExpr::Name(n) => n.clone(),
            LuaExpr::Vararg => "...".into(),
            LuaExpr::Upvalue { index, name } => {
                name.clone().unwrap_or_else(|| format!("_upval_{index}"))
            }
            LuaExpr::BinOp { op, lhs, rhs } => {
                format!("({} {op} {})", self.fmt_expr(lhs, 0), self.fmt_expr(rhs, 0))
            }
            LuaExpr::UnOp { op, operand } => {
                format!("{op}{}", self.fmt_expr(operand, 0))
            }
            LuaExpr::Call { func, args } => {
                let arg_str: Vec<String> = args.iter().map(|a| self.fmt_expr(a, 0)).collect();
                format!("{}({})", self.fmt_expr(func, 0), arg_str.join(", "))
            }
            LuaExpr::MethodCall { obj, method, args } => {
                let arg_str: Vec<String> = args.iter().map(|a| self.fmt_expr(a, 0)).collect();
                format!(
                    "{}:{}({})",
                    self.fmt_expr(obj, 0),
                    method,
                    arg_str.join(", ")
                )
            }
            LuaExpr::Index { table, key } => {
                format!("{}[{}]", self.fmt_expr(table, 0), self.fmt_expr(key, 0))
            }
            LuaExpr::Field { table, field } => {
                format!("{}.{}", self.fmt_expr(table, 0), field)
            }
            LuaExpr::FuncExpr {
                params,
                body,
                has_vararg,
            } => {
                let mut p = params.clone();
                if *has_vararg {
                    p.push("...".into());
                }
                let body_str = self.fmt_stmts(body, 1);
                format!("function({})\n{}\nend", p.join(", "), body_str)
            }
            LuaExpr::Table(fields) => {
                let items: Vec<String> = fields
                    .iter()
                    .map(|f| match f {
                        TableField::Keyed { key, value } => {
                            format!("[{}] = {}", self.fmt_expr(key, 0), self.fmt_expr(value, 0))
                        }
                        TableField::Indexed(v) => self.fmt_expr(v, 0),
                    })
                    .collect();
                format!("{{{}}}", items.join(", "))
            }
        }
    }

    #[must_use] 
    pub fn format_stmt(&self, stmt: &LuaStmt, depth: usize) -> String {
        self.fmt_stmt(stmt, depth)
    }

    fn fmt_stmt(&self, stmt: &LuaStmt, depth: usize) -> String {
        let ind = self.indent(depth);
        match stmt {
            LuaStmt::Assign { targets, values } => {
                let ts: Vec<String> = targets.iter().map(|t| self.fmt_expr(t, 0)).collect();
                let vs: Vec<String> = values.iter().map(|v| self.fmt_expr(v, 0)).collect();
                format!("{ind}{} = {}", ts.join(", "), vs.join(", "))
            }
            LuaStmt::Local { names, values } => {
                let vs: Vec<String> = values.iter().map(|v| self.fmt_expr(v, 0)).collect();
                if vs.is_empty() {
                    format!("{ind}local {}", names.join(", "))
                } else {
                    format!("{ind}local {} = {}", names.join(", "), vs.join(", "))
                }
            }
            LuaStmt::Call(e) => format!("{ind}{}", self.fmt_expr(e, 0)),
            LuaStmt::Do(body) => {
                format!(
                    "{ind}do\n{}\n{ind}end",
                    self.fmt_stmts(body, depth + 1),
                    ind = ind
                )
            }
            LuaStmt::While { cond, body } => {
                format!(
                    "{ind}while {} do\n{}\n{ind}end",
                    self.fmt_expr(cond, 0),
                    self.fmt_stmts(body, depth + 1)
                )
            }
            LuaStmt::Repeat { body, until } => {
                format!(
                    "{ind}repeat\n{}\n{ind}until {}",
                    self.fmt_stmts(body, depth + 1),
                    self.fmt_expr(until, 0)
                )
            }
            _ => self.fmt_stmt_compound(stmt, depth),
        }
    }

    /// Formatting for the multi-line compound statements (loops, `if`,
    /// `return`, jumps and function definitions).
    fn fmt_stmt_compound(&self, stmt: &LuaStmt, depth: usize) -> String {
        let ind = self.indent(depth);
        match stmt {
            LuaStmt::NumericFor {
                var,
                start,
                limit,
                step,
                body,
            } => {
                let step_str = step
                    .as_ref()
                    .map(|s| format!(", {}", self.fmt_expr(s, 0)))
                    .unwrap_or_default();
                format!(
                    "{ind}for {var} = {}, {}{step_str} do\n{}\n{ind}end",
                    self.fmt_expr(start, 0),
                    self.fmt_expr(limit, 0),
                    self.fmt_stmts(body, depth + 1)
                )
            }
            LuaStmt::GenericFor { vars, exprs, body } => {
                let es: Vec<String> = exprs.iter().map(|e| self.fmt_expr(e, 0)).collect();
                format!(
                    "{ind}for {} in {} do\n{}\n{ind}end",
                    vars.join(", "),
                    es.join(", "),
                    self.fmt_stmts(body, depth + 1)
                )
            }
            LuaStmt::If {
                cond,
                then_body,
                elseif,
                else_body,
            } => {
                let mut s = format!(
                    "{ind}if {} then\n{}",
                    self.fmt_expr(cond, 0),
                    self.fmt_stmts(then_body, depth + 1)
                );
                for (ei_cond, ei_body) in elseif {
                    let _ = write!(s, 
                        "\n{ind}elseif {} then\n{}",
                        self.fmt_expr(ei_cond, 0),
                        self.fmt_stmts(ei_body, depth + 1)
                    );
                }
                if let Some(eb) = else_body {
                    let _ = write!(s, "\n{ind}else\n{}", self.fmt_stmts(eb, depth + 1));
                }
                let _ = write!(s, "\n{ind}end");
                s
            }
            LuaStmt::Return(vals) => {
                if vals.is_empty() {
                    format!("{ind}return")
                } else {
                    let vs: Vec<String> = vals.iter().map(|v| self.fmt_expr(v, 0)).collect();
                    format!("{ind}return {}", vs.join(", "))
                }
            }
            LuaStmt::Break => format!("{ind}break"),
            LuaStmt::Goto(lbl) => format!("{ind}goto {lbl}"),
            LuaStmt::Label(lbl) => format!("{ind}::{lbl}::"),
            LuaStmt::FuncDef {
                name,
                params,
                body,
                has_vararg,
            } => {
                let mut p = params.clone();
                if *has_vararg {
                    p.push("...".into());
                }
                format!(
                    "{ind}function {}({})\n{}\n{ind}end",
                    self.fmt_expr(name, 0),
                    p.join(", "),
                    self.fmt_stmts(body, depth + 1)
                )
            }
            // Handled by `fmt_stmt`; unreachable via that entry point.
            _ => String::new(),
        }
    }

    fn fmt_stmts(&self, stmts: &[LuaStmt], depth: usize) -> String {
        stmts
            .iter()
            .map(|s| self.fmt_stmt(s, depth))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Format a complete function.
    #[must_use] 
    pub fn format_function(&self, func: &DecompileFunction) -> String {
        let mut out = String::new();
        let name = func.name.as_deref().unwrap_or("?");
        let mut params = func.params.clone();
        if func.has_vararg {
            params.push("...".into());
        }
        let _ = writeln!(out, "function {}({})", name, params.join(", "));
        out.push_str(&self.fmt_stmts(&func.stmts, 1));
        out.push_str("\nend\n");
        out
    }
}

// ---------------------------------------------------------------------------
// Lua AST analysis utilities
// ---------------------------------------------------------------------------

/// Counts occurrences of each variable name used in expressions.
#[derive(Debug, Default)]
pub struct VariableUsageCounter {
    pub counts: HashMap<String, usize>,
}

impl VariableUsageCounter {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn count_expr(&mut self, expr: &LuaExpr) {
        match expr {
            LuaExpr::Name(n) => {
                if let Some(c) = self.counts.get_mut(n) {
                    *c += 1;
                } else {
                    self.counts.insert(n.clone(), 1);
                }
            }
            LuaExpr::BinOp { lhs, rhs, .. } => {
                self.count_expr(lhs);
                self.count_expr(rhs);
            }
            LuaExpr::UnOp { operand, .. } => self.count_expr(operand),
            LuaExpr::Call { func, args } => {
                self.count_expr(func);
                for a in args {
                    self.count_expr(a);
                }
            }
            LuaExpr::MethodCall { obj, args, .. } => {
                self.count_expr(obj);
                for a in args {
                    self.count_expr(a);
                }
            }
            LuaExpr::Field { table, .. } => self.count_expr(table),
            LuaExpr::Index { table, key } => {
                self.count_expr(table);
                self.count_expr(key);
            }
            LuaExpr::Table(fields) => {
                for f in fields {
                    match f {
                        TableField::Keyed { key, value } => {
                            self.count_expr(key);
                            self.count_expr(value);
                        }
                        TableField::Indexed(v) => self.count_expr(v),
                    }
                }
            }
            LuaExpr::FuncExpr { body, .. } => self.count_stmts(body),
            _ => {}
        }
    }

    pub fn count_stmts(&mut self, stmts: &[LuaStmt]) {
        for stmt in stmts {
            match stmt {
                LuaStmt::Assign { targets, values } => {
                    for e in targets.iter().chain(values) {
                        self.count_expr(e);
                    }
                }
                LuaStmt::Local { values, .. } => {
                    for e in values {
                        self.count_expr(e);
                    }
                }
                LuaStmt::Call(e) => self.count_expr(e),
                LuaStmt::Return(vals) => {
                    for v in vals {
                        self.count_expr(v);
                    }
                }
                LuaStmt::While { cond, body } => {
                    self.count_expr(cond);
                    self.count_stmts(body);
                }
                LuaStmt::Repeat { body, until } => {
                    self.count_stmts(body);
                    self.count_expr(until);
                }
                LuaStmt::If {
                    cond,
                    then_body,
                    elseif,
                    else_body,
                } => {
                    self.count_expr(cond);
                    self.count_stmts(then_body);
                    for (ec, eb) in elseif {
                        self.count_expr(ec);
                        self.count_stmts(eb);
                    }
                    if let Some(eb) = else_body {
                        self.count_stmts(eb);
                    }
                }
                LuaStmt::NumericFor {
                    start,
                    limit,
                    step,
                    body,
                    ..
                } => {
                    self.count_expr(start);
                    self.count_expr(limit);
                    if let Some(s) = step {
                        self.count_expr(s);
                    }
                    self.count_stmts(body);
                }
                LuaStmt::GenericFor { exprs, body, .. } => {
                    for e in exprs {
                        self.count_expr(e);
                    }
                    self.count_stmts(body);
                }
                _ => {}
            }
        }
    }

    #[must_use] 
    pub fn most_used(&self) -> Option<(&str, usize)> {
        self.counts
            .iter()
            .max_by_key(|&(_, &c)| c)
            .map(|(n, &c)| (n.as_str(), c))
    }
}

/// Checks whether a Lua AST is well-formed.
#[derive(Debug, Default)]
pub struct AstValidator {
    pub errors: Vec<String>,
}

impl AstValidator {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate_stmts(&mut self, stmts: &[LuaStmt]) {
        for (i, stmt) in stmts.iter().enumerate() {
            match stmt {
                LuaStmt::Return(_) if i < stmts.len() - 1 => {
                    self.errors
                        .push(format!("return at index {i} is not last statement"));
                }
                LuaStmt::While { body, .. } | LuaStmt::Do(body) => self.validate_stmts(body),
                LuaStmt::If {
                    then_body,
                    elseif,
                    else_body,
                    ..
                } => {
                    self.validate_stmts(then_body);
                    for (_, b) in elseif {
                        self.validate_stmts(b);
                    }
                    if let Some(eb) = else_body {
                        self.validate_stmts(eb);
                    }
                }
                _ => {}
            }
        }
    }

    #[must_use] 
    pub const fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

// ---------------------------------------------------------------------------
// LuaDecompiler
// ---------------------------------------------------------------------------

/// Top-level Lua decompiler facade.
#[derive(Debug, Default)]
pub struct LuaDecompiler {
    pub formatter: LuaFormatter,
    pub upvalue_resolver: UpvalueResolver,
}

impl LuaDecompiler {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Decompile a function and return formatted source.
    #[must_use] 
    pub fn decompile_to_source(&self, func: &DecompileFunction) -> String {
        self.formatter.format_function(func)
    }

    /// Resolve all upvalues in a statement list.
    #[must_use] 
    pub fn resolve_upvalues(&self, stmts: Vec<LuaStmt>) -> Vec<LuaStmt> {
        stmts.into_iter().map(|s| self.resolve_stmt(s)).collect()
    }

    fn resolve_stmt(&self, stmt: LuaStmt) -> LuaStmt {
        match stmt {
            LuaStmt::Assign { targets, values } => LuaStmt::Assign {
                targets: targets
                    .into_iter()
                    .map(|e| self.upvalue_resolver.resolve_expr(e))
                    .collect(),
                values: values
                    .into_iter()
                    .map(|e| self.upvalue_resolver.resolve_expr(e))
                    .collect(),
            },
            LuaStmt::Local { names, values } => LuaStmt::Local {
                names,
                values: values
                    .into_iter()
                    .map(|e| self.upvalue_resolver.resolve_expr(e))
                    .collect(),
            },
            LuaStmt::Return(vals) => LuaStmt::Return(
                vals.into_iter()
                    .map(|e| self.upvalue_resolver.resolve_expr(e))
                    .collect(),
            ),
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt() -> LuaFormatter {
        LuaFormatter::new()
    }

    // --- BinOp / UnOp display --------------------------------------------

    #[test]
    fn test_binop_display() {
        assert_eq!(BinOp::Add.to_string(), "+");
        assert_eq!(BinOp::Concat.to_string(), "..");
        assert_eq!(BinOp::IDiv.to_string(), "//");
    }

    #[test]
    fn test_unop_display() {
        assert_eq!(UnOp::Not.to_string(), "not ");
        assert_eq!(UnOp::Len.to_string(), "#");
    }

    // --- LuaConst display ------------------------------------------------

    #[test]
    fn test_const_nil() {
        assert_eq!(LuaConst::Nil.to_string(), "nil");
    }

    #[test]
    fn test_const_bool_true() {
        assert_eq!(LuaConst::Bool(true).to_string(), "true");
    }

    #[test]
    fn test_const_int() {
        assert_eq!(LuaConst::Int(42).to_string(), "42");
    }

    #[test]
    fn test_const_str() {
        assert!(LuaConst::Str("hi".into()).to_string().contains("hi"));
    }

    // --- Expression formatting -------------------------------------------

    #[test]
    fn test_expr_name() {
        let e = LuaExpr::Name("x".into());
        assert_eq!(fmt().format_expr(&e), "x");
    }

    #[test]
    fn test_expr_binop() {
        let e = LuaExpr::BinOp {
            op: BinOp::Add,
            lhs: Box::new(LuaExpr::Name("a".into())),
            rhs: Box::new(LuaExpr::Const(LuaConst::Int(1))),
        };
        let s = fmt().format_expr(&e);
        assert!(s.contains('+'));
        assert!(s.contains('a'));
    }

    #[test]
    fn test_expr_unop_neg() {
        let e = LuaExpr::UnOp {
            op: UnOp::Neg,
            operand: Box::new(LuaExpr::Name("x".into())),
        };
        assert!(fmt().format_expr(&e).contains('-'));
    }

    #[test]
    fn test_expr_call() {
        let e = LuaExpr::Call {
            func: Box::new(LuaExpr::Name("print".into())),
            args: vec![LuaExpr::Const(LuaConst::Str("hello".into()))],
        };
        let s = fmt().format_expr(&e);
        assert!(s.starts_with("print("));
    }

    #[test]
    fn test_expr_field() {
        let e = LuaExpr::Field {
            table: Box::new(LuaExpr::Name("t".into())),
            field: "x".into(),
        };
        assert_eq!(fmt().format_expr(&e), "t.x");
    }

    #[test]
    fn test_expr_index() {
        let e = LuaExpr::Index {
            table: Box::new(LuaExpr::Name("t".into())),
            key: Box::new(LuaExpr::Const(LuaConst::Int(1))),
        };
        assert_eq!(fmt().format_expr(&e), "t[1]");
    }

    #[test]
    fn test_expr_vararg() {
        assert_eq!(fmt().format_expr(&LuaExpr::Vararg), "...");
    }

    #[test]
    fn test_expr_table_empty() {
        let e = LuaExpr::Table(vec![]);
        assert_eq!(fmt().format_expr(&e), "{}");
    }

    #[test]
    fn test_expr_upvalue_with_name() {
        let e = LuaExpr::Upvalue {
            index: 0,
            name: Some("ENV".into()),
        };
        assert_eq!(fmt().format_expr(&e), "ENV");
    }

    #[test]
    fn test_expr_upvalue_without_name() {
        let e = LuaExpr::Upvalue {
            index: 2,
            name: None,
        };
        assert!(fmt().format_expr(&e).contains("_upval_2"));
    }

    // --- Statement formatting --------------------------------------------

    #[test]
    fn test_stmt_assign() {
        let s = LuaStmt::Assign {
            targets: vec![LuaExpr::Name("x".into())],
            values: vec![LuaExpr::Const(LuaConst::Int(0))],
        };
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains("x = 0"));
    }

    #[test]
    fn test_stmt_local() {
        let s = LuaStmt::Local {
            names: vec!["y".into()],
            values: vec![LuaExpr::Const(LuaConst::Nil)],
        };
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains("local y = nil"));
    }

    #[test]
    fn test_stmt_return_empty() {
        let s = LuaStmt::Return(vec![]);
        assert!(fmt().format_stmt(&s, 0).contains("return"));
    }

    #[test]
    fn test_stmt_break() {
        let s = LuaStmt::Break;
        assert!(fmt().format_stmt(&s, 0).contains("break"));
    }

    #[test]
    fn test_stmt_while() {
        let s = LuaStmt::While {
            cond: LuaExpr::Const(LuaConst::Bool(true)),
            body: vec![LuaStmt::Break],
        };
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains("while true do"));
        assert!(out.contains("end"));
    }

    #[test]
    fn test_stmt_if() {
        let s = LuaStmt::If {
            cond: LuaExpr::Name("x".into()),
            then_body: vec![LuaStmt::Return(vec![])],
            elseif: vec![],
            else_body: None,
        };
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains("if x then"));
        assert!(out.contains("end"));
    }

    #[test]
    fn test_stmt_numeric_for() {
        let s = LuaStmt::NumericFor {
            var: "i".into(),
            start: LuaExpr::Const(LuaConst::Int(1)),
            limit: LuaExpr::Const(LuaConst::Int(10)),
            step: None,
            body: vec![],
        };
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains("for i = 1, 10 do"));
    }

    #[test]
    fn test_stmt_goto_label() {
        let s = LuaStmt::Goto("continue".into());
        assert!(fmt().format_stmt(&s, 0).contains("goto continue"));
        let l = LuaStmt::Label("continue".into());
        assert!(fmt().format_stmt(&l, 0).contains("::continue::"));
    }

    // --- UpvalueResolver -------------------------------------------------

    #[test]
    fn test_upvalue_resolver_registered() {
        let mut r = UpvalueResolver::new();
        r.register(0, "_ENV");
        assert_eq!(r.resolve(0), "_ENV");
    }

    #[test]
    fn test_upvalue_resolver_fallback() {
        let r = UpvalueResolver::new();
        assert_eq!(r.resolve(3), "_upval_3");
    }

    #[test]
    fn test_upvalue_resolver_resolves_expr() {
        let mut r = UpvalueResolver::new();
        r.register(0, "env");
        let e = LuaExpr::Upvalue {
            index: 0,
            name: None,
        };
        let resolved = r.resolve_expr(e);
        assert_eq!(resolved, LuaExpr::Name("env".into()));
    }

    // --- LuaDecompiler ---------------------------------------------------

    #[test]
    fn test_decompiler_format_function() {
        let mut f = DecompileFunction::new();
        f.stmts.push(LuaStmt::Return(vec![]));
        let d = LuaDecompiler::new();
        let src = d.decompile_to_source(&f);
        assert!(src.contains("function"));
        assert!(src.contains("return"));
        assert!(src.contains("end"));
    }

    #[test]
    fn test_decompiler_named_function() {
        let f = DecompileFunction::new().with_name("greet");
        let src = LuaDecompiler::new().decompile_to_source(&f);
        assert!(src.contains("greet"));
    }

    // --- Additional expression tests ---

    #[test]
    fn test_expr_method_call() {
        let e = LuaExpr::MethodCall {
            obj: Box::new(LuaExpr::Name("obj".into())),
            method: "doIt".into(),
            args: vec![LuaExpr::Const(LuaConst::Int(1))],
        };
        let s = fmt().format_expr(&e);
        assert!(s.contains("obj:doIt"));
    }

    #[test]
    fn test_expr_func_expr() {
        let e = LuaExpr::FuncExpr {
            params: vec!["x".into(), "y".into()],
            body: vec![LuaStmt::Return(vec![LuaExpr::BinOp {
                op: BinOp::Add,
                lhs: Box::new(LuaExpr::Name("x".into())),
                rhs: Box::new(LuaExpr::Name("y".into())),
            }])],
            has_vararg: false,
        };
        let s = fmt().format_expr(&e);
        assert!(s.contains("function(x, y)"));
        assert!(s.contains("return"));
    }

    #[test]
    fn test_expr_func_expr_vararg() {
        let e = LuaExpr::FuncExpr {
            params: vec!["x".into()],
            body: vec![],
            has_vararg: true,
        };
        let s = fmt().format_expr(&e);
        assert!(s.contains("..."));
    }

    #[test]
    fn test_expr_table_with_fields() {
        let e = LuaExpr::Table(vec![
            TableField::Indexed(LuaExpr::Const(LuaConst::Int(1))),
            TableField::Keyed {
                key: LuaExpr::Const(LuaConst::Str("k".into())),
                value: LuaExpr::Const(LuaConst::Int(2)),
            },
        ]);
        let s = fmt().format_expr(&e);
        assert!(s.contains('{'));
        assert!(s.contains('}'));
    }

    #[test]
    fn test_expr_binop_or() {
        let e = LuaExpr::BinOp {
            op: BinOp::Or,
            lhs: Box::new(LuaExpr::Name("a".into())),
            rhs: Box::new(LuaExpr::Name("b".into())),
        };
        assert!(fmt().format_expr(&e).contains("or"));
    }

    // --- Additional statement tests ---

    #[test]
    fn test_stmt_do_block() {
        let s = LuaStmt::Do(vec![LuaStmt::Break]);
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains("do"));
        assert!(out.contains("end"));
    }

    #[test]
    fn test_stmt_repeat() {
        let s = LuaStmt::Repeat {
            body: vec![LuaStmt::Break],
            until: LuaExpr::Const(LuaConst::Bool(true)),
        };
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains("repeat"));
        assert!(out.contains("until true"));
    }

    #[test]
    fn test_stmt_generic_for() {
        let s = LuaStmt::GenericFor {
            vars: vec!["k".into(), "v".into()],
            exprs: vec![LuaExpr::Call {
                func: Box::new(LuaExpr::Name("pairs".into())),
                args: vec![LuaExpr::Name("t".into())],
            }],
            body: vec![],
        };
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains("for k, v in"));
        assert!(out.contains("pairs(t)"));
    }

    #[test]
    fn test_stmt_if_with_else() {
        let s = LuaStmt::If {
            cond: LuaExpr::Name("x".into()),
            then_body: vec![LuaStmt::Return(vec![LuaExpr::Const(LuaConst::Int(1))])],
            elseif: vec![],
            else_body: Some(vec![LuaStmt::Return(vec![LuaExpr::Const(LuaConst::Int(
                0,
            ))])]),
        };
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains("else"));
        assert!(out.contains("return 1"));
    }

    #[test]
    fn test_stmt_if_with_elseif() {
        let s = LuaStmt::If {
            cond: LuaExpr::Name("a".into()),
            then_body: vec![],
            elseif: vec![(LuaExpr::Name("b".into()), vec![])],
            else_body: None,
        };
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains("elseif b then"));
    }

    #[test]
    fn test_stmt_numeric_for_with_step() {
        let s = LuaStmt::NumericFor {
            var: "i".into(),
            start: LuaExpr::Const(LuaConst::Int(0)),
            limit: LuaExpr::Const(LuaConst::Int(100)),
            step: Some(LuaExpr::Const(LuaConst::Int(2))),
            body: vec![],
        };
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains(", 2 do"));
    }

    #[test]
    fn test_stmt_func_def() {
        let s = LuaStmt::FuncDef {
            name: LuaExpr::Name("foo".into()),
            params: vec!["x".into()],
            body: vec![LuaStmt::Return(vec![LuaExpr::Name("x".into())])],
            has_vararg: false,
        };
        let out = fmt().format_stmt(&s, 0);
        assert!(out.contains("function foo(x)"));
    }

    // --- UpvalueResolver additional ---

    #[test]
    fn test_upvalue_resolver_nested_binop() {
        let mut r = UpvalueResolver::new();
        r.register(0, "x");
        let e = LuaExpr::BinOp {
            op: BinOp::Add,
            lhs: Box::new(LuaExpr::Upvalue {
                index: 0,
                name: None,
            }),
            rhs: Box::new(LuaExpr::Const(LuaConst::Int(1))),
        };
        let resolved = r.resolve_expr(e);
        if let LuaExpr::BinOp { lhs, .. } = resolved {
            assert_eq!(*lhs, LuaExpr::Name("x".into()));
        } else {
            panic!("expected BinOp");
        }
    }

    // --- Decompiler additional ---

    #[test]
    fn test_decompiler_resolve_upvalues_in_assign() {
        let mut d = LuaDecompiler::new();
        d.upvalue_resolver.register(0, "_ENV");
        let stmts = vec![LuaStmt::Assign {
            targets: vec![LuaExpr::Upvalue {
                index: 0,
                name: None,
            }],
            values: vec![LuaExpr::Const(LuaConst::Nil)],
        }];
        let resolved = d.resolve_upvalues(stmts);
        if let LuaStmt::Assign { targets, .. } = &resolved[0] {
            assert_eq!(targets[0], LuaExpr::Name("_ENV".into()));
        }
    }

    #[test]
    fn test_decompile_function_default() {
        let f = DecompileFunction::default();
        assert!(f.name.is_none());
        assert!(f.stmts.is_empty());
    }

    #[test]
    fn test_decompile_function_with_params() {
        let mut f = DecompileFunction::new();
        f.params = vec!["a".into(), "b".into()];
        f.has_vararg = true;
        let src = LuaDecompiler::new().decompile_to_source(&f);
        assert!(src.contains("a, b, ..."));
    }

    #[test]
    fn test_lua_const_float() {
        assert!(LuaConst::Float(1.5).to_string().contains("1.5"));
    }

    #[test]
    fn test_binop_pow() {
        assert_eq!(BinOp::Pow.to_string(), "^");
    }

    #[test]
    fn test_binop_shl() {
        assert_eq!(BinOp::Shl.to_string(), "<<");
    }

    #[test]
    fn test_unop_bnot() {
        assert_eq!(UnOp::BNot.to_string(), "~");
    }

    #[test]
    fn test_formatter_with_tab_indent() {
        let fmt = LuaFormatter::new().with_indent("\t");
        let s = LuaStmt::Return(vec![]);
        assert!(fmt.format_stmt(&s, 1).starts_with('\t'));
    }

    // --- VariableUsageCounter ---

    #[test]
    fn test_var_counter_simple_assign() {
        let mut vc = VariableUsageCounter::new();
        vc.count_stmts(&[LuaStmt::Assign {
            targets: vec![LuaExpr::Name("x".into())],
            values: vec![LuaExpr::Name("y".into())],
        }]);
        assert_eq!(vc.counts.get("x"), Some(&1));
        assert_eq!(vc.counts.get("y"), Some(&1));
    }

    #[test]
    fn test_var_counter_most_used() {
        let mut vc = VariableUsageCounter::new();
        for _ in 0..3 {
            vc.count_expr(&LuaExpr::Name("x".into()));
        }
        vc.count_expr(&LuaExpr::Name("y".into()));
        let (name, count) = vc.most_used().unwrap();
        assert_eq!(name, "x");
        assert_eq!(count, 3);
    }

    #[test]
    fn test_var_counter_empty() {
        let vc = VariableUsageCounter::new();
        assert!(vc.most_used().is_none());
    }

    #[test]
    fn test_var_counter_binop_counts_both() {
        let mut vc = VariableUsageCounter::new();
        vc.count_expr(&LuaExpr::BinOp {
            op: BinOp::Add,
            lhs: Box::new(LuaExpr::Name("a".into())),
            rhs: Box::new(LuaExpr::Name("a".into())),
        });
        assert_eq!(vc.counts.get("a"), Some(&2));
    }

    // --- AstValidator ---

    #[test]
    fn test_validator_valid_stmts() {
        let mut v = AstValidator::new();
        v.validate_stmts(&[LuaStmt::Return(vec![])]);
        assert!(v.is_valid());
    }

    #[test]
    fn test_validator_return_not_last() {
        let mut v = AstValidator::new();
        v.validate_stmts(&[
            LuaStmt::Return(vec![]),
            LuaStmt::Break, // return followed by more code
        ]);
        assert!(!v.is_valid());
    }

    #[test]
    fn test_validator_empty_stmts() {
        let mut v = AstValidator::new();
        v.validate_stmts(&[]);
        assert!(v.is_valid());
    }

    // --- LuaFormatter count_calls ---

    #[test]
    fn test_count_calls_none() {
        let stmts = vec![LuaStmt::Break];
        assert_eq!(LuaFormatter::count_calls(&stmts), 0);
    }

    #[test]
    fn test_count_calls_one() {
        let stmts = vec![LuaStmt::Call(LuaExpr::Call {
            func: Box::new(LuaExpr::Name("f".into())),
            args: vec![],
        })];
        assert_eq!(LuaFormatter::count_calls(&stmts), 1);
    }
}
