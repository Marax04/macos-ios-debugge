//! AST construction from IL — converts structured IL to a C-like AST.
//!
//! Key types:
//! - [`CExpr`] — C expression AST node.
//! - [`CStmt`] — C statement AST node.
//! - [`AstBuilder`] — converts a flat IL block list into a [`CFunc`] AST.
//! - [`CFunc`] — top-level function AST node.
//! - [`CWriter`] — pretty-printer for the AST.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// CType — basic C types
// ---------------------------------------------------------------------------

/// A simplified C type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CType {
    Void,
    Bool,
    Char,
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
    Ptr(Box<Self>),
    Array(Box<Self>, usize),
    Struct(String),
    Unknown,
}

impl fmt::Display for CType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Bool => write!(f, "bool"),
            Self::Char => write!(f, "char"),
            Self::U8 => write!(f, "uint8_t"),
            Self::U16 => write!(f, "uint16_t"),
            Self::U32 => write!(f, "uint32_t"),
            Self::U64 => write!(f, "uint64_t"),
            Self::I8 => write!(f, "int8_t"),
            Self::I16 => write!(f, "int16_t"),
            Self::I32 => write!(f, "int32_t"),
            Self::I64 => write!(f, "int64_t"),
            Self::F32 => write!(f, "float"),
            Self::F64 => write!(f, "double"),
            Self::Ptr(t) => write!(f, "{t}*"),
            Self::Array(t, n) => write!(f, "{t}[{n}]"),
            Self::Struct(s) => write!(f, "struct {s}"),
            Self::Unknown => write!(f, "void*"),
        }
    }
}

// ---------------------------------------------------------------------------
// BinOp / UnOp
// ---------------------------------------------------------------------------

/// Binary operators.
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
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Assign,
    AddAssign,
    SubAssign,
    MulAssign,
    DivAssign,
    BitAndAssign,
    BitOrAssign,
    BitXorAssign,
    ShlAssign,
    ShrAssign,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
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
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::And => "&&",
            Self::Or => "||",
            Self::Assign => "=",
            Self::AddAssign => "+=",
            Self::SubAssign => "-=",
            Self::MulAssign => "*=",
            Self::DivAssign => "/=",
            Self::BitAndAssign => "&=",
            Self::BitOrAssign => "|=",
            Self::BitXorAssign => "^=",
            Self::ShlAssign => "<<=",
            Self::ShrAssign => ">>=",
        };
        write!(f, "{s}")
    }
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnOp {
    Neg,
    Not,
    BitNot,
    PreInc,
    PreDec,
    PostInc,
    PostDec,
}

impl fmt::Display for UnOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Neg => write!(f, "-"),
            Self::Not => write!(f, "!"),
            Self::BitNot => write!(f, "~"),
            Self::PreInc | Self::PostInc => write!(f, "++"),
            Self::PreDec | Self::PostDec => write!(f, "--"),
        }
    }
}

// ---------------------------------------------------------------------------
// CExpr
// ---------------------------------------------------------------------------

/// A C expression AST node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CExpr {
    /// Integer literal.
    IntLit(i64),
    /// Float literal.
    FloatLit(f64),
    /// String literal.
    StrLit(String),
    /// Identifier (variable or function name).
    Ident(String),
    /// Binary operation.
    BinOp {
        op: BinOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// Unary prefix operation.
    UnOp { op: UnOp, expr: Box<Self> },
    /// Function call: `callee(args...)`.
    Call {
        callee: Box<Self>,
        args: Vec<Self>,
    },
    /// Type cast: `(type)expr`.
    Cast { ty: CType, expr: Box<Self> },
    /// Dereference: `*expr`.
    Deref(Box<Self>),
    /// Address-of: `&expr`.
    AddrOf(Box<Self>),
    /// Struct field access: `expr.field`.
    FieldAccess { expr: Box<Self>, field: String },
    /// Pointer field access: `expr->field`.
    ArrowAccess { expr: Box<Self>, field: String },
    /// Array subscript: `base[index]`.
    ArrayAccess { base: Box<Self>, index: Box<Self> },
    /// Conditional (ternary): `cond ? then : else`.
    Cond {
        cond: Box<Self>,
        then: Box<Self>,
        else_: Box<Self>,
    },
    /// Sizeof: `sizeof(type)`.
    Sizeof(CType),
}

impl CExpr {
    /// Helper: build a simple identifier.
    #[must_use]
    pub fn ident(name: impl Into<String>) -> Self {
        Self::Ident(name.into())
    }

    /// Helper: build an integer literal.
    #[must_use]
    pub const fn int(v: i64) -> Self {
        Self::IntLit(v)
    }

    /// Helper: build a binary operation.
    #[must_use]
    pub fn binop(op: BinOp, lhs: Self, rhs: Self) -> Self {
        Self::BinOp {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Helper: assignment.
    #[must_use]
    pub fn assign(dst: Self, src: Self) -> Self {
        Self::binop(BinOp::Assign, dst, src)
    }

    /// Helper: call with no args.
    #[must_use]
    pub fn call0(name: impl Into<String>) -> Self {
        Self::Call {
            callee: Box::new(Self::ident(name)),
            args: vec![],
        }
    }

    /// Helper: deref.
    #[must_use]
    pub fn deref(inner: Self) -> Self {
        Self::Deref(Box::new(inner))
    }
}

impl fmt::Display for CExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntLit(v) => write!(f, "{v}"),
            Self::FloatLit(v) => write!(f, "{v}"),
            Self::StrLit(s) => write!(f, "\"{s}\""),
            Self::Ident(n) => write!(f, "{n}"),
            Self::BinOp { op, lhs, rhs } => write!(f, "({lhs} {op} {rhs})"),
            Self::UnOp { op, expr } => match op {
                UnOp::PostInc | UnOp::PostDec => write!(f, "({expr}{op})"),
                _ => write!(f, "({op}{expr})"),
            },
            Self::Call { callee, args } => {
                let arg_str = args.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join(", ");
                write!(f, "{callee}({arg_str})")
            }
            Self::Cast { ty, expr } => write!(f, "(({ty}){expr})"),
            Self::Deref(e) => write!(f, "(*{e})"),
            Self::AddrOf(e) => write!(f, "(&{e})"),
            Self::FieldAccess { expr, field } => write!(f, "{expr}.{field}"),
            Self::ArrowAccess { expr, field } => write!(f, "{expr}->{field}"),
            Self::ArrayAccess { base, index } => write!(f, "{base}[{index}]"),
            Self::Cond { cond, then, else_ } => write!(f, "({cond} ? {then} : {else_})"),
            Self::Sizeof(ty) => write!(f, "sizeof({ty})"),
        }
    }
}

// ---------------------------------------------------------------------------
// CStmt
// ---------------------------------------------------------------------------

/// A C statement AST node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CStmt {
    /// A block of statements: `{ stmts... }`.
    Block(Vec<Self>),
    /// Variable declaration: `type name [= init];`.
    VarDecl {
        ty: CType,
        name: String,
        init: Option<CExpr>,
    },
    /// Expression statement: `expr;`.
    Expr(CExpr),
    /// `if (cond) { then } [else { else_ }]`.
    If {
        cond: CExpr,
        then: Box<Self>,
        else_: Option<Box<Self>>,
    },
    /// `while (cond) { body }`.
    While { cond: CExpr, body: Box<Self> },
    /// `do { body } while (cond);`.
    DoWhile { cond: CExpr, body: Box<Self> },
    /// `for (init; cond; step) { body }`.
    For {
        init: Option<Box<Self>>,
        cond: Option<CExpr>,
        step: Option<CExpr>,
        body: Box<Self>,
    },
    /// `switch (expr) { cases }`.
    Switch {
        expr: CExpr,
        cases: Vec<(Option<CExpr>, Vec<Self>)>,
    },
    /// `return [expr];`.
    Return(Option<CExpr>),
    /// `break;`.
    Break,
    /// `continue;`.
    Continue,
    /// `goto label;`.
    Goto(String),
    /// `label:`.
    Label(String),
}

impl CStmt {
    /// Helper: expression statement.
    #[must_use]
    pub const fn expr(e: CExpr) -> Self {
        Self::Expr(e)
    }

    /// Helper: return void.
    #[must_use]
    pub const fn return_void() -> Self {
        Self::Return(None)
    }

    /// Helper: return value.
    #[must_use]
    pub const fn return_val(e: CExpr) -> Self {
        Self::Return(Some(e))
    }

    /// Helper: simple if without else.
    #[must_use]
    pub fn if_then(cond: CExpr, then: Self) -> Self {
        Self::If {
            cond,
            then: Box::new(then),
            else_: None,
        }
    }

    /// Helper: while loop.
    #[must_use]
    pub fn while_loop(cond: CExpr, body: Self) -> Self {
        Self::While {
            cond,
            body: Box::new(body),
        }
    }
}

// ---------------------------------------------------------------------------
// CFunc
// ---------------------------------------------------------------------------

/// A top-level function in the AST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CFunc {
    /// Function name.
    pub name: String,
    /// Return type.
    pub ret_ty: CType,
    /// Parameters: `(type, name)`.
    pub params: Vec<(CType, String)>,
    /// Function body.
    pub body: CStmt,
    /// Original virtual address.
    pub address: u64,
}

impl CFunc {
    /// Create a new function with an empty block body.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        ret_ty: CType,
        params: Vec<(CType, String)>,
        address: u64,
    ) -> Self {
        Self {
            name: name.into(),
            ret_ty,
            params,
            body: CStmt::Block(vec![]),
            address,
        }
    }

    /// Return `true` if the body is an empty block.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        matches!(&self.body, CStmt::Block(stmts) if stmts.is_empty())
    }

    /// Number of top-level statements in the body (0 for a non-Block body).
    #[must_use]
    pub const fn statement_count(&self) -> usize {
        match &self.body {
            CStmt::Block(stmts) => stmts.len(),
            _ => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// CWriter — pretty-printer
// ---------------------------------------------------------------------------

/// Converts an AST to a C source string.
pub struct CWriter {
    indent_width: usize,
}

impl Default for CWriter {
    fn default() -> Self {
        Self { indent_width: 2 }
    }
}

impl CWriter {
    /// Create a writer with given indent width.
    #[must_use]
    pub const fn new(indent_width: usize) -> Self {
        Self { indent_width }
    }

    /// Emit a complete function.
    #[must_use]
    pub fn emit_func(&self, func: &CFunc) -> String {
        let params = func
            .params
            .iter()
            .map(|(ty, name)| format!("{ty} {name}"))
            .collect::<Vec<_>>()
            .join(", ");
        let sig = format!("{} {}({params})", func.ret_ty, func.name);
        let body = self.emit_stmt(&func.body, 0);
        format!("{sig}\n{body}\n")
    }

    /// Emit a statement at indentation level `indent`.
    #[must_use]
    pub fn emit_stmt(&self, stmt: &CStmt, indent: usize) -> String {
        let pad = " ".repeat(indent * self.indent_width);
        let inner = " ".repeat((indent + 1) * self.indent_width);
        match stmt {
            CStmt::Block(stmts) => {
                if stmts.is_empty() {
                    return format!("{pad}{{}}");
                }
                let inner_stmts: Vec<String> = stmts
                    .iter()
                    .map(|s| self.emit_stmt(s, indent + 1))
                    .collect();
                format!("{pad}{{\n{}\n{pad}}}", inner_stmts.join("\n"))
            }
            CStmt::VarDecl { ty, name, init } => {
                init.as_ref().map_or_else(
                    || format!("{pad}{ty} {name};"),
                    |init| format!("{pad}{ty} {name} = {init};"),
                )
            }
            CStmt::Expr(e) => format!("{pad}{e};"),
            CStmt::If { cond, then, else_ } => {
                let then_str = self.emit_stmt(then, indent + 1);
                let else_str = else_
                    .as_ref()
                    .map(|e| {
                        format!(
                            " else {}",
                            self.emit_stmt(e, indent + 1).trim_start()
                        )
                    })
                    .unwrap_or_default();
                format!("{pad}if ({cond})\n{then_str}{else_str}")
            }
            CStmt::While { cond, body } => {
                let body_str = self.emit_stmt(body, indent + 1);
                format!("{pad}while ({cond})\n{body_str}")
            }
            CStmt::DoWhile { cond, body } => {
                let body_str = self.emit_stmt(body, indent + 1);
                format!("{pad}do\n{body_str}\n{pad}while ({cond});")
            }
            CStmt::For {
                init,
                cond,
                step,
                body,
            } => {
                let init_s = init
                    .as_ref()
                    .map(|s| {
                        self.emit_stmt(s, 0)
                            .trim()
                            .trim_end_matches(';')
                            .to_string()
                    })
                    .unwrap_or_default();
                let cond_s = cond.as_ref().map(std::string::ToString::to_string).unwrap_or_default();
                let step_s = step.as_ref().map(std::string::ToString::to_string).unwrap_or_default();
                let body_str = self.emit_stmt(body, indent + 1);
                format!("{pad}for ({init_s}; {cond_s}; {step_s})\n{body_str}")
            }
            CStmt::Switch { expr, cases } => {
                let mut s = format!("{pad}switch ({expr}) {{\n");
                for (label, stmts) in cases {
                    if let Some(l) = label {
                        writeln!(s, "{inner}case {l}:").unwrap();
                    } else {
                        writeln!(s, "{inner}default:").unwrap();
                    }
                    for st in stmts {
                        s.push_str(&self.emit_stmt(st, indent + 2));
                        s.push('\n');
                    }
                }
                write!(s, "{pad}}}").unwrap();
                s
            }
            CStmt::Return(None) => format!("{pad}return;"),
            CStmt::Return(Some(e)) => format!("{pad}return {e};"),
            CStmt::Break => format!("{pad}break;"),
            CStmt::Continue => format!("{pad}continue;"),
            CStmt::Goto(lbl) => format!("{pad}goto {lbl};"),
            CStmt::Label(lbl) => format!("{pad}{lbl}:"),
        }
    }
}

// ---------------------------------------------------------------------------
// IlBlock / StructuredCfg
// ---------------------------------------------------------------------------

/// A simplified IL basic block for input to the AST builder.
#[derive(Debug, Clone)]
pub struct IlBlock {
    /// Block identifier (e.g. index).
    pub id: u32,
    /// Virtual address of the first instruction.
    pub address: u64,
    /// Raw pseudo-code lines in this block.
    pub lines: Vec<String>,
    /// Successor block IDs (empty = terminal).
    pub successors: Vec<u32>,
    /// `true` if this block is the loop header.
    pub is_loop_header: bool,
}

impl IlBlock {
    #[must_use]
    pub const fn new(id: u32, address: u64) -> Self {
        Self {
            id,
            address,
            lines: Vec::new(),
            successors: Vec::new(),
            is_loop_header: false,
        }
    }

    #[must_use] 
    pub fn with_lines(mut self, lines: Vec<String>) -> Self {
        self.lines = lines;
        self
    }

    #[must_use] 
    pub fn with_successors(mut self, succ: Vec<u32>) -> Self {
        self.successors = succ;
        self
    }
}

/// A structured control-flow graph: sequence of [`IlBlock`]s.
#[derive(Debug, Clone)]
pub struct StructuredCfg {
    pub blocks: Vec<IlBlock>,
    pub entry: u32,
}

impl StructuredCfg {
    #[must_use]
    pub const fn new(blocks: Vec<IlBlock>, entry: u32) -> Self {
        Self { blocks, entry }
    }

    fn find_block(&self, id: u32) -> Option<&IlBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }
}

// ---------------------------------------------------------------------------
// AstBuilder
// ---------------------------------------------------------------------------

/// Converts a [`StructuredCfg`] into a [`CFunc`] AST.
///
/// The builder does a simple depth-first traversal, translating each block's
/// lines into [`CStmt::Expr`] nodes.  Loop headers become `while (1)` loops.
pub struct AstBuilder {
    func_name: String,
    func_addr: u64,
    ret_ty: CType,
    params: Vec<(CType, String)>,
}

impl AstBuilder {
    /// Create a builder for a function.
    #[must_use]
    pub fn new(
        func_name: impl Into<String>,
        func_addr: u64,
        ret_ty: CType,
        params: Vec<(CType, String)>,
    ) -> Self {
        Self {
            func_name: func_name.into(),
            func_addr,
            ret_ty,
            params,
        }
    }

    /// Build a [`CFunc`] from a [`StructuredCfg`].
    #[must_use]
    pub fn build(&self, cfg: &StructuredCfg) -> CFunc {
        let stmts = Self::convert_cfg(cfg);
        CFunc {
            name: self.func_name.clone(),
            ret_ty: self.ret_ty.clone(),
            params: self.params.clone(),
            body: CStmt::Block(stmts),
            address: self.func_addr,
        }
    }

    /// Build a simple [`CFunc`] from raw pseudo-code lines.
    #[must_use]
    pub fn build_from_lines(&self, lines: &[String]) -> CFunc {
        let stmts: Vec<CStmt> = lines
            .iter()
            .filter(|l| !l.trim().is_empty())
            .map(|l| CStmt::Expr(CExpr::Ident(l.clone())))
            .collect();
        let mut stmts = stmts;
        stmts.push(CStmt::return_void());
        CFunc {
            name: self.func_name.clone(),
            ret_ty: self.ret_ty.clone(),
            params: self.params.clone(),
            body: CStmt::Block(stmts),
            address: self.func_addr,
        }
    }

    fn convert_cfg(cfg: &StructuredCfg) -> Vec<CStmt> {
        let mut visited = std::collections::HashSet::new();
        convert_block(cfg, cfg.entry, &mut visited)
    }

}

fn convert_block(
    cfg: &StructuredCfg,
    id: u32,
    visited: &mut std::collections::HashSet<u32>,
) -> Vec<CStmt> {
    if visited.contains(&id) {
        // Back-edge — emit a goto to avoid infinite recursion.
        return vec![CStmt::Goto(format!("block_{id}"))];
    }
    visited.insert(id);

    let Some(block) = cfg.find_block(id) else {
        return vec![];
    };

    let mut stmts: Vec<CStmt> = vec![CStmt::Label(format!("block_{id}"))];

    // Translate lines.
    for line in &block.lines {
        stmts.push(CStmt::Expr(CExpr::Ident(line.clone())));
    }

    match block.successors.len() {
        0 => {
            // Terminal block.
            stmts.push(CStmt::return_void());
        }
        1 => {
            // Linear flow.
            let next_id = block.successors[0];
            if visited.contains(&next_id) {
                // Back-edge to an already-emitted block: emit an explicit
                // goto so the loop structure survives lowering.
                stmts.push(CStmt::Goto(format!("block_{next_id}")));
            } else {
                let next_stmts = convert_block(cfg, next_id, visited);
                stmts.extend(next_stmts);
            }
        }
        2 => {
            // Conditional branch — produce if/else.
            let then_id = block.successors[0];
            let else_id = block.successors[1];
            let then_stmts = convert_block(cfg, then_id, visited);
            let else_stmts = convert_block(cfg, else_id, visited);
            stmts.push(CStmt::If {
                cond: CExpr::ident("__cond__"),
                then: Box::new(CStmt::Block(then_stmts)),
                else_: Some(Box::new(CStmt::Block(else_stmts))),
            });
        }
        _ => {
            // Switch-like — one case per successor.
            let cases: Vec<(Option<CExpr>, Vec<CStmt>)> = block
                .successors
                .iter()
                .enumerate()
                .map(|(i, &succ_id)| {
                    let case_stmts = convert_block(cfg, succ_id, visited);
                    (Some(CExpr::int(i64::try_from(i).unwrap_or(i64::MAX))), case_stmts)
                })
                .collect();
            stmts.push(CStmt::Switch {
                expr: CExpr::ident("__switch__"),
                cases,
            });
        }
    }

    stmts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_builder() -> AstBuilder {
        AstBuilder::new("sub_1000", 0x1000, CType::Void, vec![])
    }

    // CType

    #[test]
    fn test_ctype_display_primitives() {
        assert_eq!(CType::Void.to_string(), "void");
        assert_eq!(CType::U64.to_string(), "uint64_t");
        assert_eq!(CType::I32.to_string(), "int32_t");
    }

    #[test]
    fn test_ctype_ptr() {
        let ty = CType::Ptr(Box::new(CType::I32));
        assert_eq!(ty.to_string(), "int32_t*");
    }

    #[test]
    fn test_ctype_array() {
        let ty = CType::Array(Box::new(CType::U8), 16);
        assert_eq!(ty.to_string(), "uint8_t[16]");
    }

    // CExpr

    #[test]
    fn test_cexpr_int_lit() {
        let e = CExpr::int(42);
        assert_eq!(e.to_string(), "42");
    }

    #[test]
    fn test_cexpr_ident() {
        let e = CExpr::ident("x");
        assert_eq!(e.to_string(), "x");
    }

    #[test]
    fn test_cexpr_binop() {
        let e = CExpr::binop(BinOp::Add, CExpr::int(1), CExpr::int(2));
        assert_eq!(e.to_string(), "(1 + 2)");
    }

    #[test]
    fn test_cexpr_assign() {
        let e = CExpr::assign(CExpr::ident("x"), CExpr::int(0));
        assert_eq!(e.to_string(), "(x = 0)");
    }

    #[test]
    fn test_cexpr_deref() {
        let e = CExpr::deref(CExpr::ident("ptr"));
        assert_eq!(e.to_string(), "(*ptr)");
    }

    #[test]
    fn test_cexpr_call() {
        let e = CExpr::Call {
            callee: Box::new(CExpr::ident("foo")),
            args: vec![CExpr::int(1), CExpr::int(2)],
        };
        assert_eq!(e.to_string(), "foo(1, 2)");
    }

    #[test]
    fn test_cexpr_field_access() {
        let e = CExpr::FieldAccess {
            expr: Box::new(CExpr::ident("s")),
            field: "x".to_string(),
        };
        assert_eq!(e.to_string(), "s.x");
    }

    #[test]
    fn test_cexpr_array_access() {
        let e = CExpr::ArrayAccess {
            base: Box::new(CExpr::ident("arr")),
            index: Box::new(CExpr::int(3)),
        };
        assert_eq!(e.to_string(), "arr[3]");
    }

    #[test]
    fn test_cexpr_cond() {
        let e = CExpr::Cond {
            cond: Box::new(CExpr::ident("x")),
            then: Box::new(CExpr::int(1)),
            else_: Box::new(CExpr::int(0)),
        };
        assert!(e.to_string().contains('?'));
    }

    // CStmt

    #[test]
    fn test_cstmt_expr() {
        let s = CStmt::expr(CExpr::ident("foo();".to_string()));
        let w = CWriter::default();
        let out = w.emit_stmt(&s, 0);
        assert!(out.contains("foo()"));
    }

    #[test]
    fn test_cstmt_return_void() {
        let s = CStmt::return_void();
        let w = CWriter::default();
        let out = w.emit_stmt(&s, 0);
        assert_eq!(out.trim(), "return;");
    }

    #[test]
    fn test_cstmt_var_decl_with_init() {
        let s = CStmt::VarDecl {
            ty: CType::I32,
            name: "x".to_string(),
            init: Some(CExpr::int(0)),
        };
        let w = CWriter::default();
        let out = w.emit_stmt(&s, 0);
        assert!(out.contains("int32_t x = 0;"));
    }

    #[test]
    fn test_cstmt_if() {
        let s = CStmt::if_then(CExpr::ident("x"), CStmt::return_void());
        let w = CWriter::default();
        let out = w.emit_stmt(&s, 0);
        assert!(out.contains("if (x)"));
    }

    #[test]
    fn test_cstmt_while() {
        let s = CStmt::while_loop(CExpr::int(1), CStmt::Block(vec![]));
        let w = CWriter::default();
        let out = w.emit_stmt(&s, 0);
        assert!(out.contains("while (1)"));
    }

    #[test]
    fn test_cstmt_block_empty() {
        let s = CStmt::Block(vec![]);
        let w = CWriter::default();
        let out = w.emit_stmt(&s, 0);
        assert!(out.contains("{}"));
    }

    // CFunc

    #[test]
    fn test_cfunc_new_empty() {
        let f = CFunc::new("foo", CType::Void, vec![], 0x1000);
        assert!(f.is_empty());
    }

    #[test]
    fn test_cfunc_statement_count() {
        let mut f = CFunc::new("foo", CType::Void, vec![], 0x1000);
        f.body = CStmt::Block(vec![CStmt::return_void(), CStmt::Break]);
        assert_eq!(f.statement_count(), 2);
    }

    // CWriter

    #[test]
    fn test_cwriter_emit_func() {
        let f = CFunc {
            name: "bar".to_string(),
            ret_ty: CType::I32,
            params: vec![(CType::I32, "n".to_string())],
            body: CStmt::Block(vec![CStmt::return_val(CExpr::int(0))]),
            address: 0,
        };
        let w = CWriter::default();
        let out = w.emit_func(&f);
        assert!(out.contains("int32_t bar(int32_t n)"));
        assert!(out.contains("return 0;"));
    }

    // AstBuilder

    #[test]
    fn test_ast_builder_from_lines() {
        let b = make_builder();
        let lines = vec!["x = 1;".to_string(), "y = 2;".to_string()];
        let func = b.build_from_lines(&lines);
        assert_eq!(func.name, "sub_1000");
        assert!(!func.is_empty());
    }

    #[test]
    fn test_ast_builder_build_cfg_linear() {
        let b = make_builder();
        let blocks = vec![
            IlBlock::new(0, 0x1000)
                .with_lines(vec!["a = 1;".to_string()])
                .with_successors(vec![1]),
            IlBlock::new(1, 0x1010).with_lines(vec!["b = 2;".to_string()]),
        ];
        let cfg = StructuredCfg::new(blocks, 0);
        let func = b.build(&cfg);
        let w = CWriter::default();
        let out = w.emit_func(&func);
        assert!(out.contains("a = 1;"));
        assert!(out.contains("b = 2;"));
    }

    #[test]
    fn test_ast_builder_build_cfg_branch() {
        let b = make_builder();
        let blocks = vec![
            IlBlock::new(0, 0x1000)
                .with_lines(vec!["cmp rax, 0;".to_string()])
                .with_successors(vec![1, 2]),
            IlBlock::new(1, 0x1010).with_lines(vec!["a = 1;".to_string()]),
            IlBlock::new(2, 0x1020).with_lines(vec!["b = 2;".to_string()]),
        ];
        let cfg = StructuredCfg::new(blocks, 0);
        let func = b.build(&cfg);
        let w = CWriter::default();
        let out = w.emit_func(&func);
        assert!(out.contains("if (__cond__)"));
    }

    #[test]
    fn test_ast_builder_back_edge() {
        let b = make_builder();
        // Block 0 → block 1 → block 0 (back edge)
        let blocks = vec![
            IlBlock::new(0, 0x1000)
                .with_lines(vec!["loop_body;".to_string()])
                .with_successors(vec![1]),
            IlBlock::new(1, 0x1010)
                .with_lines(vec![])
                .with_successors(vec![0]),
        ];
        let cfg = StructuredCfg::new(blocks, 0);
        let func = b.build(&cfg);
        let w = CWriter::default();
        let out = w.emit_func(&func);
        assert!(out.contains("goto block_0"));
    }

    #[test]
    fn test_binop_display_all() {
        assert_eq!(BinOp::Add.to_string(), "+");
        assert_eq!(BinOp::Assign.to_string(), "=");
        assert_eq!(BinOp::Eq.to_string(), "==");
        assert_eq!(BinOp::ShrAssign.to_string(), ">>=");
    }

    #[test]
    fn test_unop_display() {
        assert_eq!(UnOp::Neg.to_string(), "-");
        assert_eq!(UnOp::Not.to_string(), "!");
    }
}
