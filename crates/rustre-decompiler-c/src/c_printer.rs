//! C code pretty printer.
//!
//! [`CPrinter`] takes a simplified C AST and emits well-formatted
//! C pseudocode with configurable style options.

use serde::{Deserialize, Serialize};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// PrintStyle
// ─────────────────────────────────────────────────────────────────────────────

/// Indentation style.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndentStyle {
    Spaces(u8),
    Tabs,
}

impl IndentStyle {
    #[must_use]
    pub fn make(&self, level: usize) -> String {
        match self {
            Self::Spaces(n) => " ".repeat(*n as usize * level),
            Self::Tabs => "\t".repeat(level),
        }
    }
}

/// Brace placement style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BraceStyle {
    /// Opening brace on the same line (K&R / Linux style).
    SameLine,
    /// Opening brace on its own line (Allman style).
    NewLine,
}

/// Bitfield of boolean options for [`PrintStyle`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PrintFlags(u8);

impl PrintFlags {
    const USE_TYPEDEF: u8 = 0b0001;
    const EMIT_COMMENTS: u8 = 0b0010;
    const SPACE_AFTER_KEYWORDS: u8 = 0b0100;
    const SPACE_INSIDE_PARENS: u8 = 0b1000;

    #[must_use] pub const fn default_flags() -> Self { Self(0b0111) } // all except space_inside_parens
    #[must_use] pub const fn use_typedef(self) -> bool { self.0 & Self::USE_TYPEDEF != 0 }
    #[must_use] pub const fn emit_comments(self) -> bool { self.0 & Self::EMIT_COMMENTS != 0 }
    #[must_use] pub const fn space_after_keywords(self) -> bool { self.0 & Self::SPACE_AFTER_KEYWORDS != 0 }
    #[must_use] pub const fn space_inside_parens(self) -> bool { self.0 & Self::SPACE_INSIDE_PARENS != 0 }
}

impl Default for PrintFlags {
    fn default() -> Self { Self::default_flags() }
}

/// Full printing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintStyle {
    pub indent: IndentStyle,
    pub brace_style: BraceStyle,
    pub line_width: usize,
    /// Boolean flags (typedef, comments, spacing).
    pub flags: PrintFlags,
}

impl Default for PrintStyle {
    fn default() -> Self {
        Self {
            indent: IndentStyle::Spaces(4),
            brace_style: BraceStyle::SameLine,
            line_width: 120,
            flags: PrintFlags::default_flags(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// C AST types (simplified)
// ─────────────────────────────────────────────────────────────────────────────

/// A C type node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CType {
    Void,
    Bool,
    Int(u8, bool), // (bits, signed)
    Float(u8),     // (bits)
    Pointer(Box<Self>),
    Array(Box<Self>, Option<usize>),
    Struct(String),
    Enum(String),
    Typedef(String),
    FuncPtr { ret: Box<Self>, params: Vec<Self> },
    Const(Box<Self>),
    Volatile(Box<Self>),
}

impl fmt::Display for CType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => f.write_str("void"),
            Self::Bool => f.write_str("bool"),
            Self::Int(32, true) => f.write_str("int"),
            Self::Int(64, true) => f.write_str("long long"),
            Self::Int(32, false) => f.write_str("unsigned int"),
            Self::Int(64, false) => f.write_str("unsigned long long"),
            Self::Int(b, true) => write!(f, "int{b}_t"),
            Self::Int(b, false) => write!(f, "uint{b}_t"),
            Self::Float(32) => f.write_str("float"),
            Self::Float(64) => f.write_str("double"),
            Self::Float(b) => write!(f, "float{b}"),
            Self::Pointer(inner) => write!(f, "{inner}*"),
            Self::Array(inner, Some(n)) => write!(f, "{inner}[{n}]"),
            Self::Array(inner, None) => write!(f, "{inner}[]"),
            Self::Struct(name) => write!(f, "struct {name}"),
            Self::Enum(name) => write!(f, "enum {name}"),
            Self::Typedef(name) => f.write_str(name),
            Self::FuncPtr { ret, params } => {
                let ps: Vec<String> = params.iter().map(|p| format!("{p}")).collect();
                write!(f, "(*)({})", ps.join(", "))?;
                write!(f, " /* ret={ret} */")
            }
            Self::Const(inner) => write!(f, "const {inner}"),
            Self::Volatile(inner) => write!(f, "volatile {inner}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CExpr — C expression nodes
// ─────────────────────────────────────────────────────────────────────────────

/// Operator precedence (higher = tighter binding).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Precedence {
    Comma = 0,
    Assign = 1,
    Ternary = 2,
    LogOr = 3,
    LogAnd = 4,
    BitOr = 5,
    BitXor = 6,
    BitAnd = 7,
    Equality = 8,
    Relational = 9,
    Shift = 10,
    Additive = 11,
    Multiplicative = 12,
    Unary = 13,
    Postfix = 14,
    Primary = 15,
}

/// A binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    LogAnd,
    LogOr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Assign,
    AddAssign,
    SubAssign,
    MulAssign,
    DivAssign,
    BitAndAssign,
    BitOrAssign,
    ShlAssign,
    ShrAssign,
}

impl BinOp {
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::BitAnd => "&",
            Self::BitOr => "|",
            Self::BitXor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::LogAnd => "&&",
            Self::LogOr => "||",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Assign => "=",
            Self::AddAssign => "+=",
            Self::SubAssign => "-=",
            Self::MulAssign => "*=",
            Self::DivAssign => "/=",
            Self::BitAndAssign => "&=",
            Self::BitOrAssign => "|=",
            Self::ShlAssign => "<<=",
            Self::ShrAssign => ">>=",
        }
    }

    #[must_use]
    pub const fn precedence(self) -> Precedence {
        match self {
            Self::Mul | Self::Div | Self::Mod => Precedence::Multiplicative,
            Self::Add | Self::Sub => Precedence::Additive,
            Self::Shl | Self::Shr => Precedence::Shift,
            Self::Lt | Self::Le | Self::Gt | Self::Ge => Precedence::Relational,
            Self::Eq | Self::Ne => Precedence::Equality,
            Self::BitAnd => Precedence::BitAnd,
            Self::BitXor => Precedence::BitXor,
            Self::BitOr => Precedence::BitOr,
            Self::LogAnd => Precedence::LogAnd,
            Self::LogOr => Precedence::LogOr,
            Self::Assign
            | Self::AddAssign
            | Self::SubAssign
            | Self::MulAssign
            | Self::DivAssign
            | Self::BitAndAssign
            | Self::BitOrAssign
            | Self::ShlAssign
            | Self::ShrAssign => Precedence::Assign,
        }
    }
}

/// A unary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnOp {
    Neg,
    Not,
    BitNot,
    Deref,
    AddrOf,
    PreInc,
    PreDec,
}

impl UnOp {
    #[must_use]
    pub const fn symbol_prefix(self) -> &'static str {
        match self {
            Self::Neg => "-",
            Self::Not => "!",
            Self::BitNot => "~",
            Self::Deref => "*",
            Self::AddrOf => "&",
            Self::PreInc => "++",
            Self::PreDec => "--",
        }
    }
}

/// A C expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CExpr {
    IntLit(i64),
    UIntLit(u64),
    FloatLit(f64),
    StrLit(String),
    CharLit(char),
    Null,
    Ident(String),
    Cast(Box<CType>, Box<Self>),
    BinOp(BinOp, Box<Self>, Box<Self>),
    UnOp(UnOp, Box<Self>),
    Call(Box<Self>, Vec<Self>),
    Index(Box<Self>, Box<Self>),
    Member(Box<Self>, String, bool), // expr.field (false) or expr->field (true)
    Ternary(Box<Self>, Box<Self>, Box<Self>),
    SizeOf(Box<CType>),
    Comma(Box<Self>, Box<Self>),
}

// ─────────────────────────────────────────────────────────────────────────────
// CStmt — C statement nodes
// ─────────────────────────────────────────────────────────────────────────────

/// A C statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CStmt {
    Expr(CExpr),
    Decl {
        ty: CType,
        name: String,
        init: Option<CExpr>,
    },
    Return(Option<CExpr>),
    If {
        cond: CExpr,
        then: Vec<Self>,
        else_: Option<Vec<Self>>,
    },
    While {
        cond: CExpr,
        body: Vec<Self>,
    },
    DoWhile {
        cond: CExpr,
        body: Vec<Self>,
    },
    For {
        init: Option<Box<Self>>,
        cond: Option<CExpr>,
        update: Option<CExpr>,
        body: Vec<Self>,
    },
    Switch {
        cond: CExpr,
        cases: Vec<SwitchCase>,
    },
    Break,
    Continue,
    Goto(String),
    Label(String),
    Block(Vec<Self>),
    Comment(String),
}

/// A case in a switch statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchCase {
    pub value: Option<i64>, // None = default
    pub body: Vec<CStmt>,
}

/// A complete function definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CFuncDef {
    pub ret_type: CType,
    pub name: String,
    pub params: Vec<(CType, String)>,
    pub is_variadic: bool,
    pub body: Vec<CStmt>,
    pub attributes: Vec<String>,
    pub address: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// ExprPrinter
// ─────────────────────────────────────────────────────────────────────────────

/// Prints [`CExpr`] nodes with correct precedence parenthesization.
pub struct ExprPrinter<'a> {
    style: &'a PrintStyle,
}

impl<'a> ExprPrinter<'a> {
    #[must_use]
    pub const fn new(style: &'a PrintStyle) -> Self {
        Self { style }
    }

    /// Borrow the [`PrintStyle`] this printer was created with so callers can
    /// reuse the same configuration when constructing sibling printers.
    #[must_use]
    pub const fn style(&self) -> &'a PrintStyle {
        self.style
    }

    #[must_use]
    pub fn print(&self, expr: &CExpr) -> String {
        self.print_prec(expr, Precedence::Comma)
    }

    fn print_prec(&self, expr: &CExpr, outer_prec: Precedence) -> String {
        match expr {
            CExpr::IntLit(n) => format!("{n}L"),
            CExpr::UIntLit(n) => format!("{n}UL"),
            CExpr::FloatLit(f) => {
                if (*f - f.trunc()).abs() < f64::EPSILON {
                    format!("{f}.0")
                } else {
                    format!("{f}")
                }
            }
            CExpr::StrLit(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
            CExpr::CharLit(c) => format!("'{c}'"),
            CExpr::Null => "NULL".to_string(),
            CExpr::Ident(name) => name.clone(),
            CExpr::Cast(ty, inner) => {
                let inner_s = self.print_prec(inner, Precedence::Unary);
                format!("({ty}){inner_s}")
            }
            CExpr::UnOp(op, inner) => {
                let inner_s = self.print_prec(inner, Precedence::Unary);
                let s = format!("{}{}", op.symbol_prefix(), inner_s);
                if Precedence::Unary < outer_prec {
                    format!("({s})")
                } else {
                    s
                }
            }
            CExpr::BinOp(op, lhs, rhs) => {
                let prec = op.precedence();
                let ls = self.print_prec(lhs, prec);
                let rs = self.print_prec(rhs, prec);
                let s = format!("{} {} {}", ls, op.symbol(), rs);
                if prec < outer_prec {
                    format!("({s})")
                } else {
                    s
                }
            }
            CExpr::Call(func, args) => {
                let f = self.print_prec(func, Precedence::Postfix);
                let arg_strs: Vec<String> = args.iter().map(|a| self.print(a)).collect();
                format!("{}({})", f, arg_strs.join(", "))
            }
            CExpr::Index(arr, idx) => {
                let a = self.print_prec(arr, Precedence::Postfix);
                let i = self.print(idx);
                format!("{a}[{i}]")
            }
            CExpr::Member(obj, field, arrow) => {
                let o = self.print_prec(obj, Precedence::Postfix);
                let sep = if *arrow { "->" } else { "." };
                format!("{o}{sep}{field}")
            }
            CExpr::Ternary(cond, then, else_) => {
                let c = self.print(cond);
                let t = self.print(then);
                let e = self.print(else_);
                let s = format!("{c} ? {t} : {e}");
                if Precedence::Ternary < outer_prec {
                    format!("({s})")
                } else {
                    s
                }
            }
            CExpr::SizeOf(ty) => format!("sizeof({ty})"),
            CExpr::Comma(l, r) => format!("{}, {}", self.print(l), self.print(r)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StmtPrinter
// ─────────────────────────────────────────────────────────────────────────────

/// Prints [`CStmt`] nodes.
pub struct StmtPrinter<'a> {
    style: &'a PrintStyle,
    expr_printer: ExprPrinter<'a>,
}

impl<'a> StmtPrinter<'a> {
    #[must_use]
    pub const fn new(style: &'a PrintStyle) -> Self {
        Self {
            style,
            expr_printer: ExprPrinter::new(style),
        }
    }

    fn print_if(&self, cond: &CExpr, then: &[CStmt], else_: Option<&Vec<CStmt>>, indent: &str, level: usize) -> String {
        let cond_s = self.expr_printer.print(cond);
        let then_body = self.print_block(then, level);
        let else_part = else_.map_or_else(String::new, |else_stmts| {
            let eb = self.print_block(else_stmts, level);
            match self.style.brace_style {
                BraceStyle::SameLine => format!(" else {eb}"),
                BraceStyle::NewLine => format!("\n{indent}else\n{eb}"),
            }
        });
        match self.style.brace_style {
            BraceStyle::SameLine => format!("{indent}if ({cond_s}) {then_body}{else_part}"),
            BraceStyle::NewLine => format!("{indent}if ({cond_s})\n{then_body}{else_part}"),
        }
    }

    fn print_switch(&self, cond: &CExpr, cases: &[SwitchCase], indent: &str, level: usize) -> String {
        use std::fmt::Write as _;
        let c = self.expr_printer.print(cond);
        let mut out = format!("{indent}switch ({c}) {{\n");
        for case in cases {
            if let Some(v) = case.value {
                writeln!(out, "{indent}case {v}:").unwrap();
            } else {
                writeln!(out, "{indent}default:").unwrap();
            }
            for s in &case.body {
                out.push_str(&self.print_stmt(s, level + 2));
                out.push('\n');
            }
        }
        write!(out, "{indent}}}").unwrap();
        out
    }

    #[must_use]
    pub fn print_stmt(&self, stmt: &CStmt, level: usize) -> String {
        let indent = self.style.indent.make(level);
        match stmt {
            CStmt::Expr(e) => format!("{}{};", indent, self.expr_printer.print(e)),
            CStmt::Decl { ty, name, init } => {
                let init_s = init.as_ref().map(|e| format!(" = {}", self.expr_printer.print(e))).unwrap_or_default();
                format!("{indent}{ty} {name}{init_s};")
            }
            CStmt::Return(val) => {
                let v = val.as_ref().map(|e| format!(" {}", self.expr_printer.print(e))).unwrap_or_default();
                format!("{indent}return{v};")
            }
            CStmt::Break => format!("{indent}break;"),
            CStmt::Continue => format!("{indent}continue;"),
            CStmt::Goto(lbl) => format!("{indent}goto {lbl};"),
            CStmt::Label(lbl) => format!("{lbl}:"),
            CStmt::Comment(s) => format!("{indent}/* {s} */"),
            CStmt::Block(stmts) => {
                let body = stmts.iter().map(|s| self.print_stmt(s, level + 1)).collect::<Vec<_>>().join("\n");
                format!("{indent}{{\n{body}\n{indent}}}")
            }
            CStmt::If { cond, then, else_ } => self.print_if(cond, then, else_.as_ref(), &indent, level),
            CStmt::While { cond, body } => {
                let c = self.expr_printer.print(cond);
                let b = self.print_block(body, level);
                match self.style.brace_style {
                    BraceStyle::SameLine => format!("{indent}while ({c}) {b}"),
                    BraceStyle::NewLine => format!("{indent}while ({c})\n{b}"),
                }
            }
            CStmt::DoWhile { cond, body } => {
                let c = self.expr_printer.print(cond);
                let b = self.print_block(body, level);
                format!("{indent}do {b} while ({c});")
            }
            CStmt::For { init, cond, update, body } => {
                let init_s = init.as_ref().map(|s| self.print_stmt_inline(s)).unwrap_or_default();
                let cond_s = cond.as_ref().map(|e| self.expr_printer.print(e)).unwrap_or_default();
                let upd_s = update.as_ref().map(|e| self.expr_printer.print(e)).unwrap_or_default();
                let b = self.print_block(body, level);
                format!("{indent}for ({init_s}; {cond_s}; {upd_s}) {b}")
            }
            CStmt::Switch { cond, cases } => self.print_switch(cond, cases, &indent, level),
        }
    }

    fn print_stmt_inline(&self, stmt: &CStmt) -> String {
        match stmt {
            CStmt::Decl { ty, name, init } => {
                let i = init
                    .as_ref()
                    .map(|e| format!(" = {}", self.expr_printer.print(e)))
                    .unwrap_or_default();
                format!("{ty} {name}{i}")
            }
            CStmt::Expr(e) => self.expr_printer.print(e),
            _ => String::new(),
        }
    }

    fn print_block(&self, stmts: &[CStmt], level: usize) -> String {
        let indent = self.style.indent.make(level);
        let body = stmts
            .iter()
            .map(|s| self.print_stmt(s, level + 1))
            .collect::<Vec<_>>()
            .join("\n");
        format!("{{\n{body}\n{indent}}}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypePrinter
// ─────────────────────────────────────────────────────────────────────────────

/// Prints [`CType`] with optional typedef usage.
pub struct TypePrinter<'a> {
    style: &'a PrintStyle,
}

impl<'a> TypePrinter<'a> {
    #[must_use]
    pub const fn new(style: &'a PrintStyle) -> Self {
        Self { style }
    }

    /// Borrow the [`PrintStyle`] this printer was created with.
    #[must_use]
    pub const fn style(&self) -> &'a PrintStyle {
        self.style
    }

    #[must_use]
    pub fn print(&self, ty: &CType) -> String {
        format!("{ty}")
    }

    #[must_use]
    pub fn print_decl(&self, ty: &CType, name: &str) -> String {
        match ty {
            CType::Array(inner, n) => {
                let n_str = n.map_or_else(|| "[]".into(), |n| format!("[{n}]"));
                format!("{inner} {name}{n_str}")
            }
            CType::FuncPtr { ret, params } => {
                let ps: Vec<String> = params.iter().map(|p| self.print(p)).collect();
                format!("{} (*{})({})", ret, name, ps.join(", "))
            }
            other => format!("{other} {name}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FuncPrinter
// ─────────────────────────────────────────────────────────────────────────────

/// Prints a complete function definition.
pub struct FuncPrinter<'a> {
    style: &'a PrintStyle,
    stmt_printer: StmtPrinter<'a>,
    type_printer: TypePrinter<'a>,
}

impl<'a> FuncPrinter<'a> {
    #[must_use]
    pub const fn new(style: &'a PrintStyle) -> Self {
        Self {
            style,
            stmt_printer: StmtPrinter::new(style),
            type_printer: TypePrinter::new(style),
        }
    }

    #[must_use]
    pub fn print(&self, func: &CFuncDef) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        if self.style.flags.emit_comments() {
            writeln!(out, "/* 0x{:x}: {} */", func.address, func.name).unwrap();
        }
        for attr in &func.attributes {
            writeln!(out, "__attribute__(({attr}))").unwrap();
        }
        // Signature
        let params: Vec<String> = func
            .params
            .iter()
            .map(|(ty, name)| self.type_printer.print_decl(ty, name))
            .collect();
        let variadic_part = if func.is_variadic { ", ..." } else { "" };
        let ret_str = self.type_printer.print(&func.ret_type);
        write!(out, "{} {}({}{})", ret_str, func.name, params.join(", "), variadic_part).unwrap();
        // Body
        match self.style.brace_style {
            BraceStyle::SameLine => out.push_str(" {\n"),
            BraceStyle::NewLine => out.push_str("\n{\n"),
        }
        for stmt in &func.body {
            out.push_str(&self.stmt_printer.print_stmt(stmt, 1));
            out.push('\n');
        }
        out.push_str("}\n");
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CPrinter
// ─────────────────────────────────────────────────────────────────────────────

/// The main C printer — configurable, holds the [`PrintStyle`].
#[derive(Default)]
pub struct CPrinter {
    pub style: PrintStyle,
}


impl CPrinter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub const fn with_style(style: PrintStyle) -> Self {
        Self { style }
    }

    #[must_use]
    pub fn print_expr(&self, expr: &CExpr) -> String {
        ExprPrinter::new(&self.style).print(expr)
    }

    #[must_use]
    pub fn print_stmt(&self, stmt: &CStmt, level: usize) -> String {
        StmtPrinter::new(&self.style).print_stmt(stmt, level)
    }

    #[must_use]
    pub fn print_func(&self, func: &CFuncDef) -> String {
        FuncPrinter::new(&self.style).print(func)
    }

    #[must_use]
    pub fn print_type(&self, ty: &CType) -> String {
        TypePrinter::new(&self.style).print(ty)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn printer() -> CPrinter {
        CPrinter::new()
    }

    // --- CType ---

    #[test]
    fn ctype_void() {
        assert_eq!(format!("{}", CType::Void), "void");
    }

    #[test]
    fn ctype_int32() {
        assert_eq!(format!("{}", CType::Int(32, true)), "int");
    }

    #[test]
    fn ctype_uint64() {
        assert_eq!(format!("{}", CType::Int(64, false)), "unsigned long long");
    }

    #[test]
    fn ctype_ptr_to_int() {
        let t = CType::Pointer(Box::new(CType::Int(32, true)));
        assert_eq!(format!("{t}"), "int*");
    }

    #[test]
    fn ctype_const_int() {
        let t = CType::Const(Box::new(CType::Int(32, true)));
        assert_eq!(format!("{t}"), "const int");
    }

    #[test]
    fn ctype_typedef() {
        assert_eq!(format!("{}", CType::Typedef("size_t".into())), "size_t");
    }

    // --- ExprPrinter ---

    #[test]
    fn expr_int_lit() {
        let p = printer();
        assert_eq!(p.print_expr(&CExpr::IntLit(42)), "42L");
    }

    #[test]
    fn expr_null() {
        assert_eq!(printer().print_expr(&CExpr::Null), "NULL");
    }

    #[test]
    fn expr_ident() {
        assert_eq!(printer().print_expr(&CExpr::Ident("x".into())), "x");
    }

    #[test]
    fn expr_binop_add() {
        let e = CExpr::BinOp(
            BinOp::Add,
            Box::new(CExpr::IntLit(1)),
            Box::new(CExpr::IntLit(2)),
        );
        let s = printer().print_expr(&e);
        assert!(s.contains('+'));
    }

    #[test]
    fn expr_cast() {
        let e = CExpr::Cast(
            Box::new(CType::Int(32, true)),
            Box::new(CExpr::Ident("x".into())),
        );
        let s = printer().print_expr(&e);
        assert!(s.contains("(int)"));
    }

    #[test]
    fn expr_call() {
        let e = CExpr::Call(
            Box::new(CExpr::Ident("printf".into())),
            vec![CExpr::StrLit("hello".into())],
        );
        let s = printer().print_expr(&e);
        assert!(s.contains("printf"));
        assert!(s.contains("hello"));
    }

    #[test]
    fn expr_member_dot() {
        let e = CExpr::Member(Box::new(CExpr::Ident("s".into())), "x".into(), false);
        assert_eq!(printer().print_expr(&e), "s.x");
    }

    #[test]
    fn expr_member_arrow() {
        let e = CExpr::Member(Box::new(CExpr::Ident("p".into())), "y".into(), true);
        assert_eq!(printer().print_expr(&e), "p->y");
    }

    #[test]
    fn expr_sizeof() {
        let e = CExpr::SizeOf(Box::new(CType::Int(32, true)));
        assert_eq!(printer().print_expr(&e), "sizeof(int)");
    }

    #[test]
    fn expr_unop_neg() {
        let e = CExpr::UnOp(UnOp::Neg, Box::new(CExpr::IntLit(5)));
        let s = printer().print_expr(&e);
        assert!(s.contains('-'));
    }

    // --- StmtPrinter ---

    #[test]
    fn stmt_return_void() {
        let s = printer().print_stmt(&CStmt::Return(None), 0);
        assert_eq!(s, "return;");
    }

    #[test]
    fn stmt_return_expr() {
        let s = printer().print_stmt(&CStmt::Return(Some(CExpr::IntLit(0))), 0);
        assert!(s.contains("return"));
        assert!(s.contains('0'));
    }

    #[test]
    fn stmt_break() {
        assert!(printer().print_stmt(&CStmt::Break, 0).contains("break"));
    }

    #[test]
    fn stmt_decl_with_init() {
        let s = printer().print_stmt(
            &CStmt::Decl {
                ty: CType::Int(32, true),
                name: "i".into(),
                init: Some(CExpr::IntLit(0)),
            },
            0,
        );
        assert!(s.contains("int"));
        assert!(s.contains('i'));
    }

    #[test]
    fn stmt_comment() {
        let s = printer().print_stmt(&CStmt::Comment("hello".into()), 0);
        assert!(s.contains("hello"));
    }

    // --- FuncPrinter ---

    #[test]
    fn func_printer_basic() {
        let func = CFuncDef {
            ret_type: CType::Int(32, true),
            name: "add".into(),
            params: vec![
                (CType::Int(32, true), "a".into()),
                (CType::Int(32, true), "b".into()),
            ],
            is_variadic: false,
            body: vec![CStmt::Return(Some(CExpr::BinOp(
                BinOp::Add,
                Box::new(CExpr::Ident("a".into())),
                Box::new(CExpr::Ident("b".into())),
            )))],
            attributes: vec![],
            address: 0x1000,
        };
        let s = printer().print_func(&func);
        assert!(s.contains("int add("));
        assert!(s.contains("return"));
    }

    #[test]
    fn func_printer_variadic() {
        let func = CFuncDef {
            ret_type: CType::Int(32, true),
            name: "variadic".into(),
            params: vec![(CType::Pointer(Box::new(CType::Int(8, true))), "fmt".into())],
            is_variadic: true,
            body: vec![CStmt::Return(Some(CExpr::IntLit(0)))],
            attributes: vec![],
            address: 0,
        };
        let s = printer().print_func(&func);
        assert!(s.contains("..."));
    }

    #[test]
    fn func_printer_address_in_comment() {
        let func = CFuncDef {
            ret_type: CType::Void,
            name: "sub_1234".into(),
            params: vec![],
            is_variadic: false,
            body: vec![],
            attributes: vec![],
            address: 0x1234,
        };
        let s = printer().print_func(&func);
        assert!(s.contains("0x1234"));
    }

    #[test]
    fn ctype_array_display() {
        let t = CType::Array(Box::new(CType::Int(32, true)), Some(10));
        assert!(format!("{t}").contains("int"));
        assert!(format!("{t}").contains("10"));
    }
}
