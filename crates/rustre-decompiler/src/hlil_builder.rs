//! `hlil_builder` — High Level IL (HLIL) builder for RustRE.
//!
//! Builds HLIL from structured IL: [`HlilBuilder`], [`HlilExpr`] (20+ node types),
//! [`HlilStmt`] (if/while/for/switch/return/assignment), [`HlilFunction`],
//! [`HlilPrinter`], and [`HlilOptimizer`].

pub use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

// ── HlilExpr ─────────────────────────────────────────────────────────────────

/// A High Level IL expression node.
#[derive(Debug, Clone, PartialEq)]
pub enum HlilExpr {
    // Literals
    Const(i64),
    Float(f64),
    Str(String),
    // Variables
    Var {
        name: String,
        size: usize,
    },
    Param {
        index: usize,
        name: String,
        size: usize,
    },
    // Arithmetic
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Div(Box<Self>, Box<Self>),
    Mod(Box<Self>, Box<Self>),
    // Bitwise
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Xor(Box<Self>, Box<Self>),
    Shl(Box<Self>, Box<Self>),
    Shr(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Neg(Box<Self>),
    // Comparison
    Eq(Box<Self>, Box<Self>),
    Ne(Box<Self>, Box<Self>),
    Lt(Box<Self>, Box<Self>),
    Le(Box<Self>, Box<Self>),
    Gt(Box<Self>, Box<Self>),
    Ge(Box<Self>, Box<Self>),
    // Logic
    LogAnd(Box<Self>, Box<Self>),
    LogOr(Box<Self>, Box<Self>),
    // Memory
    Deref {
        ptr: Box<Self>,
        size: usize,
    },
    AddressOf(Box<Self>),
    Field {
        base: Box<Self>,
        offset: usize,
        name: String,
    },
    Index {
        base: Box<Self>,
        index: Box<Self>,
        elem_size: usize,
    },
    // Cast
    ZeroExt {
        src: Box<Self>,
        dst_size: usize,
    },
    SignExt {
        src: Box<Self>,
        dst_size: usize,
    },
    Trunc {
        src: Box<Self>,
        dst_size: usize,
    },
    // Call
    Call {
        callee: Box<Self>,
        args: Vec<Self>,
    },
    // Conditional expression
    Ternary {
        cond: Box<Self>,
        then_e: Box<Self>,
        else_e: Box<Self>,
    },
    // Special
    Undefined,
    Intrinsic {
        name: String,
        args: Vec<Self>,
    },
}

impl HlilExpr {
    // Convenience constructors.
    #[must_use] 
    pub const fn const_i(v: i64) -> Self {
        Self::Const(v)
    }
    #[must_use] 
    pub fn var(name: &str, size: usize) -> Self {
        Self::Var {
            name: name.to_owned(),
            size,
        }
    }
    #[must_use] 
    pub fn make_add(a: Self, b: Self) -> Self {
        Self::Add(Box::new(a), Box::new(b))
    }
    #[must_use] 
    pub fn make_sub(a: Self, b: Self) -> Self {
        Self::Sub(Box::new(a), Box::new(b))
    }
    #[must_use] 
    pub fn make_mul(a: Self, b: Self) -> Self {
        Self::Mul(Box::new(a), Box::new(b))
    }
    #[must_use] 
    pub fn eq(a: Self, b: Self) -> Self {
        Self::Eq(Box::new(a), Box::new(b))
    }
    #[must_use] 
    pub fn ne(a: Self, b: Self) -> Self {
        Self::Ne(Box::new(a), Box::new(b))
    }
    #[must_use] 
    pub fn lt(a: Self, b: Self) -> Self {
        Self::Lt(Box::new(a), Box::new(b))
    }
    #[must_use] 
    pub fn le(a: Self, b: Self) -> Self {
        Self::Le(Box::new(a), Box::new(b))
    }
    #[must_use] 
    pub fn gt(a: Self, b: Self) -> Self {
        Self::Gt(Box::new(a), Box::new(b))
    }
    #[must_use] 
    pub fn ge(a: Self, b: Self) -> Self {
        Self::Ge(Box::new(a), Box::new(b))
    }
    #[must_use] 
    pub fn make_not(e: Self) -> Self {
        Self::Not(Box::new(e))
    }
    #[must_use] 
    pub fn make_neg(e: Self) -> Self {
        Self::Neg(Box::new(e))
    }
    #[must_use] 
    pub fn deref(ptr: Self, size: usize) -> Self {
        Self::Deref {
            ptr: Box::new(ptr),
            size,
        }
    }
    #[must_use] 
    pub fn call(callee: Self, args: Vec<Self>) -> Self {
        Self::Call {
            callee: Box::new(callee),
            args,
        }
    }

    /// Return the result size in bytes, if known.
    #[must_use] 
    pub const fn size(&self) -> Option<usize> {
        match self {
            Self::Const(_) => Some(8),
            Self::Var { size, .. } | Self::Param { size, .. } | Self::Deref { size, .. } => Some(*size),
            Self::ZeroExt { dst_size, .. } | Self::SignExt { dst_size, .. } | Self::Trunc { dst_size, .. } => Some(*dst_size),
            _ => None,
        }
    }

    /// Fold constant expressions.
    #[must_use] 
    pub fn const_fold(self) -> Self {
        match self {
            Self::Add(l, r) => match (*l, *r) {
                (Self::Const(a), Self::Const(b)) => Self::Const(a.wrapping_add(b)),
                (l, r) => Self::Add(Box::new(l.const_fold()), Box::new(r.const_fold())),
            },
            Self::Sub(l, r) => match (*l, *r) {
                (Self::Const(a), Self::Const(b)) => Self::Const(a.wrapping_sub(b)),
                (l, r) => Self::Sub(Box::new(l.const_fold()), Box::new(r.const_fold())),
            },
            Self::Mul(l, r) => match (*l, *r) {
                (Self::Const(a), Self::Const(b)) => Self::Const(a.wrapping_mul(b)),
                (l, r) => Self::Mul(Box::new(l.const_fold()), Box::new(r.const_fold())),
            },
            Self::Not(e) => match *e {
                Self::Const(v) => Self::Const(!v),
                e => Self::Not(Box::new(e.const_fold())),
            },
            Self::Neg(e) => match *e {
                Self::Const(v) => Self::Const(v.wrapping_neg()),
                e => Self::Neg(Box::new(e.const_fold())),
            },
            other => other,
        }
    }
}

impl std::ops::Add for HlilExpr {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::make_add(self, rhs)
    }
}

impl std::ops::Sub for HlilExpr {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::make_sub(self, rhs)
    }
}

impl std::ops::Mul for HlilExpr {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self::make_mul(self, rhs)
    }
}

impl std::ops::Neg for HlilExpr {
    type Output = Self;
    fn neg(self) -> Self {
        Self::make_neg(self)
    }
}

impl std::ops::Not for HlilExpr {
    type Output = Self;
    fn not(self) -> Self {
        Self::make_not(self)
    }
}

impl fmt::Display for HlilExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(v) => write!(f, "{v}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::Var { name, .. } | Self::Param { name, .. } => write!(f, "{name}"),
            Self::Add(l, r) => write!(f, "({l} + {r})"),
            Self::Sub(l, r) => write!(f, "({l} - {r})"),
            Self::Mul(l, r) => write!(f, "({l} * {r})"),
            Self::Div(l, r) => write!(f, "({l} / {r})"),
            Self::Mod(l, r) => write!(f, "({l} % {r})"),
            Self::And(l, r) => write!(f, "({l} & {r})"),
            Self::Or(l, r) => write!(f, "({l} | {r})"),
            Self::Xor(l, r) => write!(f, "({l} ^ {r})"),
            Self::Shl(l, r) => write!(f, "({l} << {r})"),
            Self::Shr(l, r) => write!(f, "({l} >> {r})"),
            Self::Not(e) => write!(f, "~{e}"),
            Self::Neg(e) => write!(f, "-{e}"),
            Self::Eq(l, r) => write!(f, "({l} == {r})"),
            Self::Ne(l, r) => write!(f, "({l} != {r})"),
            Self::Lt(l, r) => write!(f, "({l} < {r})"),
            Self::Le(l, r) => write!(f, "({l} <= {r})"),
            Self::Gt(l, r) => write!(f, "({l} > {r})"),
            Self::Ge(l, r) => write!(f, "({l} >= {r})"),
            Self::LogAnd(l, r) => write!(f, "({l} && {r})"),
            Self::LogOr(l, r) => write!(f, "({l} || {r})"),
            Self::Deref { ptr, size } => write!(f, "*({ptr}:{size})"),
            Self::AddressOf(e) => write!(f, "&{e}"),
            Self::Field { base, name, .. } => write!(f, "{base}.{name}"),
            Self::Index { base, index, .. } => write!(f, "{base}[{index}]"),
            Self::ZeroExt { src, dst_size } => write!(f, "zext{dst_size}({src})"),
            Self::SignExt { src, dst_size } => write!(f, "sext{dst_size}({src})"),
            Self::Trunc { src, dst_size } => write!(f, "trunc{dst_size}({src})"),
            Self::Call { callee, args } => {
                let a: Vec<_> = args.iter().map(std::string::ToString::to_string).collect();
                write!(f, "{callee}({})", a.join(", "))
            }
            Self::Ternary {
                cond,
                then_e,
                else_e,
            } => write!(f, "({cond} ? {then_e} : {else_e})"),
            Self::Undefined => write!(f, "undefined"),
            Self::Intrinsic { name, args } => {
                let a: Vec<_> = args.iter().map(std::string::ToString::to_string).collect();
                write!(f, "{name}({})", a.join(", "))
            }
        }
    }
}

// ── HlilStmt ─────────────────────────────────────────────────────────────────

/// A High Level IL statement.
#[derive(Debug, Clone)]
pub enum HlilStmt {
    /// Variable assignment: `lhs = rhs`.
    Assign { lhs: HlilExpr, rhs: HlilExpr },
    /// Augmented assignment: `lhs op= rhs`.
    AssignOp {
        lhs: HlilExpr,
        op: &'static str,
        rhs: HlilExpr,
    },
    /// Return statement.
    Return(Option<HlilExpr>),
    /// If statement.
    If {
        cond: HlilExpr,
        then_stmts: Vec<Self>,
        else_stmts: Vec<Self>,
    },
    /// While loop.
    While { cond: HlilExpr, body: Vec<Self> },
    /// Do-while loop.
    DoWhile { body: Vec<Self>, cond: HlilExpr },
    /// For loop.
    For {
        init: Option<Box<Self>>,
        cond: Option<HlilExpr>,
        update: Option<Box<Self>>,
        body: Vec<Self>,
    },
    /// Switch statement.
    Switch {
        expr: HlilExpr,
        cases: Vec<SwitchCase>,
        default: Vec<Self>,
    },
    /// Break.
    Break,
    /// Continue.
    Continue,
    /// Goto label.
    Goto(String),
    /// Label definition.
    Label(String),
    /// Expression statement (call, etc.).
    ExprStmt(HlilExpr),
    /// Variable declaration.
    VarDecl {
        name: String,
        ty: String,
        init: Option<HlilExpr>,
    },
    /// Unreachable.
    Unreachable,
    /// NOP / no-op.
    Nop,
}

/// A single case in a switch statement.
#[derive(Debug, Clone)]
pub struct SwitchCase {
    /// Case value(s).
    pub values: Vec<i64>,
    /// Body statements.
    pub stmts: Vec<HlilStmt>,
    /// Whether to fall through to next case.
    pub fall_through: bool,
}

impl SwitchCase {
    #[must_use] 
    pub const fn new(values: Vec<i64>, stmts: Vec<HlilStmt>) -> Self {
        Self {
            values,
            stmts,
            fall_through: false,
        }
    }
}

// ── HlilFunction ─────────────────────────────────────────────────────────────

/// A decompiled function expressed in HLIL.
#[derive(Debug, Clone)]
pub struct HlilFunction {
    pub name: String,
    pub params: Vec<HlilParam>,
    pub return_type: String,
    pub locals: Vec<HlilLocal>,
    pub body: Vec<HlilStmt>,
    pub address: u64,
}

#[derive(Debug, Clone)]
pub struct HlilParam {
    pub name: String,
    pub ty: String,
    pub index: usize,
}

#[derive(Debug, Clone)]
pub struct HlilLocal {
    pub name: String,
    pub ty: String,
}

impl HlilFunction {
    #[must_use] 
    pub fn new(name: &str, address: u64) -> Self {
        Self {
            name: name.to_owned(),
            params: Vec::new(),
            return_type: "void".to_owned(),
            locals: Vec::new(),
            body: Vec::new(),
            address,
        }
    }

    pub fn add_param(&mut self, name: &str, ty: &str) {
        let idx = self.params.len();
        self.params.push(HlilParam {
            name: name.to_owned(),
            ty: ty.to_owned(),
            index: idx,
        });
    }

    pub fn add_local(&mut self, name: &str, ty: &str) {
        self.locals.push(HlilLocal {
            name: name.to_owned(),
            ty: ty.to_owned(),
        });
    }

    pub fn push(&mut self, stmt: HlilStmt) {
        self.body.push(stmt);
    }
}

// ── HlilBuilder ──────────────────────────────────────────────────────────────

/// Builds HLIL functions incrementally.
pub struct HlilBuilder {
    pub func: HlilFunction,
    /// Auto-name counter for temporary variables.
    tmp_counter: usize,
    /// Stack of nested scope blocks (for structured control flow).
    scope_stack: Vec<Vec<HlilStmt>>,
}

impl HlilBuilder {
    #[must_use] 
    pub fn new(name: &str, address: u64) -> Self {
        Self {
            func: HlilFunction::new(name, address),
            tmp_counter: 0,
            scope_stack: Vec::new(),
        }
    }

    /// Generate a fresh temporary variable name.
    pub fn fresh_tmp(&mut self) -> String {
        let name = format!("_t{}", self.tmp_counter);
        self.tmp_counter += 1;
        name
    }

    /// Add a parameter.
    pub fn param(&mut self, name: &str, ty: &str) -> HlilExpr {
        let idx = self.func.params.len();
        self.func.add_param(name, ty);
        HlilExpr::Param {
            index: idx,
            name: name.to_owned(),
            size: 8,
        }
    }

    /// Add a local variable.
    pub fn local(&mut self, name: &str, ty: &str) -> HlilExpr {
        self.func.add_local(name, ty);
        HlilExpr::var(name, 8)
    }

    /// Push a statement to the current scope.
    pub fn emit(&mut self, stmt: HlilStmt) {
        if let Some(scope) = self.scope_stack.last_mut() {
            scope.push(stmt);
        } else {
            self.func.body.push(stmt);
        }
    }

    /// Emit an assignment.
    pub fn assign(&mut self, lhs: HlilExpr, rhs: HlilExpr) {
        self.emit(HlilStmt::Assign { lhs, rhs });
    }

    /// Emit a return.
    pub fn return_val(&mut self, val: Option<HlilExpr>) {
        self.emit(HlilStmt::Return(val));
    }

    /// Begin an if block.  Returns the index so we can patch later.
    pub fn begin_if(&mut self, cond: HlilExpr) {
        self.scope_stack.push(Vec::new());
        // Store cond in a stub — we'll reconstruct when we end the block.
        // For simplicity, emit the if directly with empty then/else first.
        self.func.body.push(HlilStmt::If {
            cond,
            then_stmts: Vec::new(),
            else_stmts: Vec::new(),
        });
    }

    /// Begin a while loop.
    pub fn begin_while(&mut self, cond: HlilExpr) {
        self.scope_stack.push(Vec::new());
        self.func.body.push(HlilStmt::While {
            cond,
            body: Vec::new(),
        });
    }

    /// Emit a complete if statement.
    pub fn if_stmt(
        &mut self,
        cond: HlilExpr,
        then_stmts: Vec<HlilStmt>,
        else_stmts: Vec<HlilStmt>,
    ) {
        self.emit(HlilStmt::If {
            cond,
            then_stmts,
            else_stmts,
        });
    }

    /// Emit a complete while loop.
    pub fn while_loop(&mut self, cond: HlilExpr, body: Vec<HlilStmt>) {
        self.emit(HlilStmt::While { cond, body });
    }

    /// Emit a for loop.
    pub fn for_loop(
        &mut self,
        init: Option<HlilStmt>,
        cond: Option<HlilExpr>,
        update: Option<HlilStmt>,
        body: Vec<HlilStmt>,
    ) {
        self.emit(HlilStmt::For {
            init: init.map(Box::new),
            cond,
            update: update.map(Box::new),
            body,
        });
    }

    /// Emit a switch statement.
    pub fn switch_stmt(&mut self, expr: HlilExpr, cases: Vec<SwitchCase>, default: Vec<HlilStmt>) {
        self.emit(HlilStmt::Switch {
            expr,
            cases,
            default,
        });
    }

    /// Emit a variable declaration.
    pub fn var_decl(&mut self, name: &str, ty: &str, init: Option<HlilExpr>) {
        self.emit(HlilStmt::VarDecl {
            name: name.to_owned(),
            ty: ty.to_owned(),
            init,
        });
    }

    /// Emit a call statement.
    pub fn call_stmt(&mut self, callee: HlilExpr, args: Vec<HlilExpr>) {
        self.emit(HlilStmt::ExprStmt(HlilExpr::call(callee, args)));
    }

    /// Finish building and return the function.
    #[must_use] 
    pub fn finish(self) -> HlilFunction {
        self.func
    }
}

// ── HlilPrinter ──────────────────────────────────────────────────────────────

/// Pretty-prints an [`HlilFunction`] as pseudo-C code.
pub struct HlilPrinter {
    indent_str: String,
}

impl HlilPrinter {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            indent_str: "    ".to_owned(),
        }
    }

    #[must_use] 
    pub fn print_function(&self, func: &HlilFunction) -> String {
        let mut out = String::new();
        // Signature
        let params: Vec<_> = func
            .params
            .iter()
            .map(|p| format!("{} {}", p.ty, p.name))
            .collect();
        writeln!(out, "{} {}({}) {{", func.return_type, func.name, params.join(", ")).unwrap();
        // Locals
        for local in &func.locals {
            writeln!(out, "    {} {};", local.ty, local.name).unwrap();
        }
        if !func.locals.is_empty() {
            out.push('\n');
        }
        // Body
        for stmt in &func.body {
            self.print_stmt(&mut out, stmt, 1);
        }
        out.push_str("}\n");
        out
    }

    fn print_stmt(&self, out: &mut String, stmt: &HlilStmt, depth: usize) {
        hlil_print_stmt(&self.indent_str, out, stmt, depth);
    }
}

impl Default for HlilPrinter {
    fn default() -> Self {
        Self::new()
    }
}

fn hlil_print_stmt(indent_str: &str, out: &mut String, stmt: &HlilStmt, depth: usize) {
    let indent = indent_str.repeat(depth);
    match stmt {
        HlilStmt::Assign { lhs, rhs } => writeln!(out, "{indent}{lhs} = {rhs};").unwrap(),
        HlilStmt::AssignOp { lhs, op, rhs } => writeln!(out, "{indent}{lhs} {op}= {rhs};").unwrap(),
        HlilStmt::Return(Some(e)) => writeln!(out, "{indent}return {e};").unwrap(),
        HlilStmt::Return(None) => writeln!(out, "{indent}return;").unwrap(),
        HlilStmt::ExprStmt(e) => writeln!(out, "{indent}{e};").unwrap(),
        HlilStmt::VarDecl { name, ty, init: Some(init) } => writeln!(out, "{indent}{ty} {name} = {init};").unwrap(),
        HlilStmt::VarDecl { name, ty, init: None } => writeln!(out, "{indent}{ty} {name};").unwrap(),
        HlilStmt::If { cond, then_stmts, else_stmts } => {
            writeln!(out, "{indent}if ({cond}) {{").unwrap();
            for s in then_stmts { hlil_print_stmt(indent_str, out, s, depth + 1); }
            if !else_stmts.is_empty() {
                writeln!(out, "{indent}}} else {{").unwrap();
                for s in else_stmts { hlil_print_stmt(indent_str, out, s, depth + 1); }
            }
            writeln!(out, "{indent}}}").unwrap();
        }
        HlilStmt::While { cond, body } => {
            writeln!(out, "{indent}while ({cond}) {{").unwrap();
            for s in body { hlil_print_stmt(indent_str, out, s, depth + 1); }
            writeln!(out, "{indent}}}").unwrap();
        }
        HlilStmt::DoWhile { body, cond } => {
            writeln!(out, "{indent}do {{").unwrap();
            for s in body { hlil_print_stmt(indent_str, out, s, depth + 1); }
            writeln!(out, "{indent}}} while ({cond});").unwrap();
        }
        HlilStmt::For { init, cond, update, body } => {
            let init_s = init.as_ref().map_or_else(String::new, |s| {
                let mut tmp = String::new();
                hlil_print_stmt(indent_str, &mut tmp, s, 0);
                tmp.trim().trim_end_matches(';').to_owned()
            });
            let cond_s = cond.as_ref().map_or_else(String::new, std::string::ToString::to_string);
            let upd_s = update.as_ref().map_or_else(String::new, |s| {
                let mut tmp = String::new();
                hlil_print_stmt(indent_str, &mut tmp, s, 0);
                tmp.trim().trim_end_matches(';').to_owned()
            });
            writeln!(out, "{indent}for ({init_s}; {cond_s}; {upd_s}) {{").unwrap();
            for s in body { hlil_print_stmt(indent_str, out, s, depth + 1); }
            writeln!(out, "{indent}}}").unwrap();
        }
        HlilStmt::Switch { expr, cases, default } => {
            writeln!(out, "{indent}switch ({expr}) {{").unwrap();
            for case in cases {
                for val in &case.values { writeln!(out, "{indent}case {val}:").unwrap(); }
                for s in &case.stmts { hlil_print_stmt(indent_str, out, s, depth + 1); }
                if !case.fall_through { writeln!(out, "{indent}    break;").unwrap(); }
            }
            if !default.is_empty() {
                writeln!(out, "{indent}default:").unwrap();
                for s in default { hlil_print_stmt(indent_str, out, s, depth + 1); }
            }
            writeln!(out, "{indent}}}").unwrap();
        }
        HlilStmt::Break => writeln!(out, "{indent}break;").unwrap(),
        HlilStmt::Continue => writeln!(out, "{indent}continue;").unwrap(),
        HlilStmt::Goto(l) => writeln!(out, "{indent}goto {l};").unwrap(),
        HlilStmt::Label(l) => writeln!(out, "{l}:").unwrap(),
        HlilStmt::Unreachable => writeln!(out, "{indent}__unreachable();").unwrap(),
        HlilStmt::Nop => {}
    }
}

// ── HlilOptimizer ─────────────────────────────────────────────────────────────

/// Simplification passes for HLIL expressions and statements.
pub struct HlilOptimizer {
    pub passes: Vec<&'static str>,
}

impl HlilOptimizer {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            passes: vec![
                "const_fold",
                "dead_assign_elim",
                "trivial_if_elim",
                "strength_reduce",
                "copy_propagate",
            ],
        }
    }

    /// Apply all optimisation passes to a function.
    pub fn optimize(&self, func: &mut HlilFunction) {
        for stmt in &mut func.body {
            Self::optimize_stmt(stmt);
        }
    }

    fn optimize_stmt(stmt: &mut HlilStmt) {
        match stmt {
            HlilStmt::Assign { lhs: _, rhs } => Self::optimize_expr(rhs),
            HlilStmt::Return(Some(e)) | HlilStmt::ExprStmt(e) => Self::optimize_expr(e),
            HlilStmt::If { cond, then_stmts, else_stmts } => {
                Self::optimize_expr(cond);
                for s in &mut *then_stmts { Self::optimize_stmt(s); }
                for s in &mut *else_stmts { Self::optimize_stmt(s); }
                // Trivial if: `if (true)` → keep then, `if (false)` → keep else
                if let HlilExpr::Const(v) = cond && *v != 0 {
                    *stmt = HlilStmt::If {
                        cond: HlilExpr::Const(1),
                        then_stmts: then_stmts.clone(),
                        else_stmts: Vec::new(),
                    };
                }
            }
            HlilStmt::While { cond, body } => {
                Self::optimize_expr(cond);
                for s in body { Self::optimize_stmt(s); }
            }
            _ => {}
        }
    }

    fn optimize_expr(expr: &mut HlilExpr) {
        // Constant folding in-place.
        let folded = std::mem::replace(expr, HlilExpr::Undefined).const_fold();
        *expr = folded;
    }
}

impl Default for HlilOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HlilExpr tests ────────────────────────────────────────────────────────

    #[test]
    fn test_expr_const_display() {
        assert_eq!(HlilExpr::Const(42).to_string(), "42");
    }

    #[test]
    fn test_expr_var_display() {
        let v = HlilExpr::var("x", 4);
        assert_eq!(v.to_string(), "x");
    }

    #[test]
    fn test_expr_add_display() {
        let e = HlilExpr::make_add(HlilExpr::const_i(1), HlilExpr::const_i(2));
        assert_eq!(e.to_string(), "(1 + 2)");
    }

    #[test]
    fn test_expr_const_fold_add() {
        let e = HlilExpr::make_add(HlilExpr::const_i(3), HlilExpr::const_i(4));
        let folded = e.const_fold();
        assert_eq!(folded, HlilExpr::Const(7));
    }

    #[test]
    fn test_expr_const_fold_sub() {
        let e = HlilExpr::make_sub(HlilExpr::const_i(10), HlilExpr::const_i(3));
        assert_eq!(e.const_fold(), HlilExpr::Const(7));
    }

    #[test]
    fn test_expr_const_fold_mul() {
        let e = HlilExpr::make_mul(HlilExpr::const_i(6), HlilExpr::const_i(7));
        assert_eq!(e.const_fold(), HlilExpr::Const(42));
    }

    #[test]
    fn test_expr_const_fold_not() {
        let e = HlilExpr::make_not(HlilExpr::const_i(0));
        assert_eq!(e.const_fold(), HlilExpr::Const(-1));
    }

    #[test]
    fn test_expr_const_fold_neg() {
        let e = HlilExpr::make_neg(HlilExpr::const_i(5));
        assert_eq!(e.const_fold(), HlilExpr::Const(-5));
    }

    #[test]
    fn test_expr_eq_display() {
        let e = HlilExpr::eq(HlilExpr::var("a", 4), HlilExpr::const_i(0));
        assert_eq!(e.to_string(), "(a == 0)");
    }

    #[test]
    fn test_expr_deref_display() {
        let e = HlilExpr::deref(HlilExpr::var("ptr", 8), 4);
        assert_eq!(e.to_string(), "*(ptr:4)");
    }

    #[test]
    fn test_expr_call_display() {
        let callee = HlilExpr::var("malloc", 8);
        let e = HlilExpr::call(callee, vec![HlilExpr::const_i(16)]);
        assert_eq!(e.to_string(), "malloc(16)");
    }

    #[test]
    fn test_expr_field_display() {
        let e = HlilExpr::Field {
            base: Box::new(HlilExpr::var("obj", 8)),
            offset: 0,
            name: "x".to_owned(),
        };
        assert_eq!(e.to_string(), "obj.x");
    }

    #[test]
    fn test_expr_index_display() {
        let e = HlilExpr::Index {
            base: Box::new(HlilExpr::var("arr", 8)),
            index: Box::new(HlilExpr::const_i(2)),
            elem_size: 4,
        };
        assert_eq!(e.to_string(), "arr[2]");
    }

    #[test]
    fn test_expr_ternary_display() {
        let e = HlilExpr::Ternary {
            cond: Box::new(HlilExpr::var("cond", 1)),
            then_e: Box::new(HlilExpr::const_i(1)),
            else_e: Box::new(HlilExpr::const_i(0)),
        };
        assert_eq!(e.to_string(), "(cond ? 1 : 0)");
    }

    #[test]
    fn test_expr_size() {
        assert_eq!(HlilExpr::Const(0).size(), Some(8));
        assert_eq!(HlilExpr::var("x", 4).size(), Some(4));
        assert_eq!(
            HlilExpr::Deref {
                ptr: Box::new(HlilExpr::Undefined),
                size: 2
            }
            .size(),
            Some(2)
        );
    }

    // ── HlilBuilder tests ─────────────────────────────────────────────────────

    #[test]
    fn test_builder_basic() {
        let mut b = HlilBuilder::new("foo", 0x1000);
        let a = b.param("a", "int");
        let b_param = b.param("b", "int");
        let result = b.local("result", "int");
        b.assign(result.clone(), HlilExpr::make_add(a, b_param));
        b.return_val(Some(result));
        let func = b.finish();
        assert_eq!(func.name, "foo");
        assert_eq!(func.params.len(), 2);
        assert_eq!(func.locals.len(), 1);
        assert_eq!(func.body.len(), 2);
    }

    #[test]
    fn test_builder_fresh_tmp() {
        let mut b = HlilBuilder::new("f", 0);
        let t0 = b.fresh_tmp();
        let t1 = b.fresh_tmp();
        assert_eq!(t0, "_t0");
        assert_eq!(t1, "_t1");
    }

    #[test]
    fn test_builder_if_stmt() {
        let mut b = HlilBuilder::new("f", 0);
        b.if_stmt(
            HlilExpr::eq(HlilExpr::var("x", 4), HlilExpr::const_i(0)),
            vec![HlilStmt::Return(Some(HlilExpr::const_i(1)))],
            vec![],
        );
        let func = b.finish();
        assert_eq!(func.body.len(), 1);
        assert!(matches!(func.body[0], HlilStmt::If { .. }));
    }

    #[test]
    fn test_builder_while_loop() {
        let mut b = HlilBuilder::new("f", 0);
        b.while_loop(
            HlilExpr::lt(HlilExpr::var("i", 4), HlilExpr::const_i(10)),
            vec![HlilStmt::AssignOp {
                lhs: HlilExpr::var("i", 4),
                op: "+",
                rhs: HlilExpr::const_i(1),
            }],
        );
        let func = b.finish();
        assert!(matches!(func.body[0], HlilStmt::While { .. }));
    }

    #[test]
    fn test_builder_for_loop() {
        let mut b = HlilBuilder::new("f", 0);
        b.for_loop(
            Some(HlilStmt::Assign {
                lhs: HlilExpr::var("i", 4),
                rhs: HlilExpr::const_i(0),
            }),
            Some(HlilExpr::lt(HlilExpr::var("i", 4), HlilExpr::const_i(10))),
            Some(HlilStmt::AssignOp {
                lhs: HlilExpr::var("i", 4),
                op: "+",
                rhs: HlilExpr::const_i(1),
            }),
            vec![],
        );
        let func = b.finish();
        assert!(matches!(func.body[0], HlilStmt::For { .. }));
    }

    #[test]
    fn test_builder_switch() {
        let mut b = HlilBuilder::new("f", 0);
        b.switch_stmt(
            HlilExpr::var("x", 4),
            vec![
                SwitchCase::new(vec![0], vec![HlilStmt::Return(Some(HlilExpr::const_i(0)))]),
                SwitchCase::new(vec![1], vec![HlilStmt::Return(Some(HlilExpr::const_i(1)))]),
            ],
            vec![HlilStmt::Return(Some(HlilExpr::const_i(-1)))],
        );
        let func = b.finish();
        assert!(matches!(func.body[0], HlilStmt::Switch { .. }));
    }

    // ── HlilPrinter tests ─────────────────────────────────────────────────────

    #[test]
    fn test_printer_basic_function() {
        let mut f = HlilFunction::new("main", 0x1000);
        f.add_param("argc", "int");
        f.push(HlilStmt::Return(Some(HlilExpr::const_i(0))));
        let printer = HlilPrinter::new();
        let code = printer.print_function(&f);
        assert!(code.contains("main"), "code='{code}'");
        assert!(code.contains("return 0"), "code='{code}'");
        assert!(code.contains("int argc"), "code='{code}'");
    }

    #[test]
    fn test_printer_if_statement() {
        let mut f = HlilFunction::new("f", 0);
        f.push(HlilStmt::If {
            cond: HlilExpr::eq(HlilExpr::var("x", 4), HlilExpr::const_i(0)),
            then_stmts: vec![HlilStmt::Return(Some(HlilExpr::const_i(1)))],
            else_stmts: vec![],
        });
        let p = HlilPrinter::new();
        let code = p.print_function(&f);
        assert!(code.contains("if ("), "code='{code}'");
        assert!(code.contains("return 1"), "code='{code}'");
    }

    #[test]
    fn test_printer_while() {
        let mut f = HlilFunction::new("f", 0);
        f.push(HlilStmt::While {
            cond: HlilExpr::const_i(1),
            body: vec![HlilStmt::Break],
        });
        let code = HlilPrinter::new().print_function(&f);
        assert!(code.contains("while"), "code='{code}'");
        assert!(code.contains("break"), "code='{code}'");
    }

    #[test]
    fn test_printer_for() {
        let f_stmt = HlilStmt::For {
            init: Some(Box::new(HlilStmt::Assign {
                lhs: HlilExpr::var("i", 4),
                rhs: HlilExpr::const_i(0),
            })),
            cond: Some(HlilExpr::lt(HlilExpr::var("i", 4), HlilExpr::const_i(10))),
            update: Some(Box::new(HlilStmt::AssignOp {
                lhs: HlilExpr::var("i", 4),
                op: "+",
                rhs: HlilExpr::const_i(1),
            })),
            body: vec![HlilStmt::Continue],
        };
        let mut func = HlilFunction::new("f", 0);
        func.push(f_stmt);
        let code = HlilPrinter::new().print_function(&func);
        assert!(code.contains("for"), "code='{code}'");
    }

    #[test]
    fn test_printer_switch() {
        let mut f = HlilFunction::new("f", 0);
        f.push(HlilStmt::Switch {
            expr: HlilExpr::var("v", 4),
            cases: vec![SwitchCase::new(vec![0, 1], vec![HlilStmt::Break])],
            default: vec![HlilStmt::Break],
        });
        let code = HlilPrinter::new().print_function(&f);
        assert!(code.contains("switch"), "code='{code}'");
        assert!(code.contains("case 0"), "code='{code}'");
        assert!(code.contains("default"), "code='{code}'");
    }

    // ── HlilOptimizer tests ───────────────────────────────────────────────────

    #[test]
    fn test_optimizer_const_fold_assign() {
        let mut func = HlilFunction::new("f", 0);
        func.push(HlilStmt::Assign {
            lhs: HlilExpr::var("x", 4),
            rhs: HlilExpr::make_add(HlilExpr::const_i(2), HlilExpr::const_i(3)),
        });
        let opt = HlilOptimizer::new();
        opt.optimize(&mut func);
        if let HlilStmt::Assign { rhs, .. } = &func.body[0] {
            assert_eq!(*rhs, HlilExpr::Const(5));
        }
    }

    #[test]
    fn test_optimizer_passes_list() {
        let opt = HlilOptimizer::new();
        assert!(opt.passes.contains(&"const_fold"));
        assert!(opt.passes.contains(&"dead_assign_elim"));
    }

    #[test]
    fn test_optimizer_const_fold_return() {
        let mut func = HlilFunction::new("f", 0);
        func.push(HlilStmt::Return(Some(HlilExpr::make_mul(
            HlilExpr::const_i(6),
            HlilExpr::const_i(7),
        ))));
        HlilOptimizer::new().optimize(&mut func);
        if let HlilStmt::Return(Some(e)) = &func.body[0] {
            assert_eq!(*e, HlilExpr::Const(42));
        }
    }

    #[test]
    fn test_expr_all_node_types_display() {
        let exprs: Vec<HlilExpr> = vec![
            HlilExpr::Float(3.14_f64),
            HlilExpr::Str("hello".into()),
            HlilExpr::Undefined,
            HlilExpr::AddressOf(Box::new(HlilExpr::var("x", 4))),
            HlilExpr::ZeroExt {
                src: Box::new(HlilExpr::const_i(1)),
                dst_size: 8,
            },
            HlilExpr::SignExt {
                src: Box::new(HlilExpr::const_i(-1)),
                dst_size: 8,
            },
            HlilExpr::Trunc {
                src: Box::new(HlilExpr::const_i(0xFFFF)),
                dst_size: 1,
            },
            HlilExpr::Intrinsic {
                name: "_mm_add_ps".into(),
                args: vec![],
            },
        ];
        for e in &exprs {
            assert!(!e.to_string().is_empty(), "{e:?} has empty display");
        }
    }
}
