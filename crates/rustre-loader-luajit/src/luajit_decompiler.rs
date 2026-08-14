//! `LuaJIT` bytecode decompiler: lifts a `LjProto` back to structured Lua source.
//!
//! The approach is a single-pass stack-based dataflow scan that reconstructs
//! expressions and statements without a full SSA build.  Output is readable
//! Lua 5.1-compatible source text.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Write as _;

use crate::luajit_opcode_table::{LjInstrDecoder, LjOpcode};
use crate::luajit_parser::{LjConst, LjProto};

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Expression tree
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A Lua expression node in the decompiled tree.
#[derive(Debug, Clone, PartialEq)]
pub enum LjExpr {
    /// Nil literal
    Nil,
    /// Boolean literal
    Bool(bool),
    /// Integer literal (from KSHORT / KNUM)
    Int(i64),
    /// Floating-point literal
    Float(f64),
    /// String literal
    Str(String),
    /// Local variable or temporary slot reference (slot index)
    Slot(u8),
    /// Named local variable (deduced from debug info)
    Local(String),
    /// Upvalue reference
    Upvalue(u8, Option<String>),
    /// Global variable access: `_G[name]`
    Global(String),
    /// Table field access: `t[k]`
    Index(Box<Self>, Box<Self>),
    /// Table field access via string key: `t.k`
    Field(Box<Self>, String),
    /// Unary operation
    Unop(UnopKind, Box<Self>),
    /// Binary operation
    Binop(BinopKind, Box<Self>, Box<Self>),
    /// Function call expression: `f(args...)`
    Call(Box<Self>, Vec<Self>),
    /// Vararg: `...`
    Vararg,
    /// Table constructor: `{ fields... }`
    Table(Vec<TableField>),
    /// Closure (child proto index)
    Closure(u32),
    /// Multi-return placeholder (result of call that returns multiple values)
    MultiRet(Box<Self>, u8),
    /// Opaque expression we couldn't reconstruct
    Raw(String),
}

impl fmt::Display for LjExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "{s:?}"),
            Self::Slot(s) => write!(f, "v{s}"),
            Self::Local(n) => write!(f, "{n}"),
            Self::Upvalue(_i, Some(name)) => write!(f, "{name}"),
            Self::Upvalue(i, None) => write!(f, "uv{i}"),
            Self::Global(n) => write!(f, "{n}"),
            Self::Index(t, k) => write!(f, "{t}[{k}]"),
            Self::Field(t, k) => write!(f, "{t}.{k}"),
            Self::Unop(op, e) => write!(f, "{op}({e})"),
            Self::Binop(op, l, r) => write!(f, "({l} {op} {r})"),
            Self::Call(callee, args) => {
                write!(f, "{callee}(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            Self::Vararg => write!(f, "..."),
            Self::Table(fields) => {
                write!(f, "{{")?;
                for (i, fld) in fields.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{fld}")?;
                }
                write!(f, "}}")
            }
            Self::Closure(n) => write!(f, "<proto#{n}>"),
            Self::MultiRet(e, n) => write!(f, "{e} [x{n}]"),
            Self::Raw(s) => write!(f, "{s}"),
        }
    }
}

/// Table field in a constructor expression.
#[derive(Debug, Clone, PartialEq)]
pub enum TableField {
    /// `[k] = v`
    Indexed(LjExpr, LjExpr),
    /// `name = v`
    Named(String, LjExpr),
    /// Positional value
    Positional(LjExpr),
}

impl fmt::Display for TableField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Indexed(k, v) => write!(f, "[{k}] = {v}"),
            Self::Named(n, v) => write!(f, "{n} = {v}"),
            Self::Positional(e) => write!(f, "{e}"),
        }
    }
}

/// Unary operator kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnopKind { Not, Neg, Len }
impl fmt::Display for UnopKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Not => write!(f, "not"),
            Self::Neg => write!(f, "-"),
            Self::Len => write!(f, "#"),
        }
    }
}

/// Binary operator kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinopKind {
    Add, Sub, Mul, Div, Mod, Pow, Cat,
    Eq, Ne, Lt, Le, Gt, Ge,
    And, Or,
}
impl fmt::Display for BinopKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "+", Self::Sub => "-",
            Self::Mul => "*", Self::Div => "/",
            Self::Mod => "%", Self::Pow => "^",
            Self::Cat => "..", Self::Eq => "==",
            Self::Ne => "~=", Self::Lt => "<",
            Self::Le => "<=", Self::Gt => ">",
            Self::Ge => ">=", Self::And => "and",
            Self::Or => "or",
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Statement tree
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A Lua statement in the decompiled tree.
#[derive(Debug, Clone)]
pub enum LjStmt {
    /// Assignment: `targets = values`
    Assign(Vec<LjExpr>, Vec<LjExpr>),
    /// Local declaration: `local names = values`
    Local(Vec<String>, Vec<LjExpr>),
    /// Function call as statement
    Call(LjExpr),
    /// `do ... end` block
    Do(Vec<Self>),
    /// `while cond do body end`
    While(LjExpr, Vec<Self>),
    /// `repeat body until cond`
    Repeat(Vec<Self>, LjExpr),
    /// Numeric for: `for var = start, limit, step do body end`
    NumericFor { var: String, start: LjExpr, limit: LjExpr, step: LjExpr, body: Vec<Self> },
    /// Generic for: `for vars in iter do body end`
    GenericFor { vars: Vec<String>, iters: Vec<LjExpr>, body: Vec<Self> },
    /// `if cond then then_body [else else_body] end`
    If { cond: LjExpr, then_body: Vec<Self>, else_body: Vec<Self> },
    /// `return exprs`
    Return(Vec<LjExpr>),
    /// Upvalue close (internal, usually elided in output)
    UpvalueClose(u8),
    /// Raw comment / opaque
    Comment(String),
}

impl LjStmt {
    fn emit(&self, out: &mut String, indent: usize) {
        let pad: String = "  ".repeat(indent);
        match self {
            Self::Assign(targets, values) => {
                let ts: Vec<String> = targets.iter().map(|e| format!("{e}")).collect();
                let vs: Vec<String> = values.iter().map(|e| format!("{e}")).collect();
                writeln!(out, "{pad}{} = {}", ts.join(", "), vs.join(", ")).unwrap();
            }
            Self::Local(names, values) => {
                let ns = names.join(", ");
                if values.is_empty() {
                    writeln!(out, "{pad}local {ns}").unwrap();
                } else {
                    let vs: Vec<String> = values.iter().map(|e| format!("{e}")).collect();
                    writeln!(out, "{pad}local {ns} = {}", vs.join(", ")).unwrap();
                }
            }
            Self::Call(e) => writeln!(out, "{pad}{e}").unwrap(),
            Self::Do(body) => {
                writeln!(out, "{pad}do").unwrap();
                for s in body { s.emit(out, indent + 1); }
                writeln!(out, "{pad}end").unwrap();
            }
            Self::While(cond, body) => {
                writeln!(out, "{pad}while {cond} do").unwrap();
                for s in body { s.emit(out, indent + 1); }
                writeln!(out, "{pad}end").unwrap();
            }
            Self::Repeat(body, cond) => {
                writeln!(out, "{pad}repeat").unwrap();
                for s in body { s.emit(out, indent + 1); }
                writeln!(out, "{pad}until {cond}").unwrap();
            }
            Self::NumericFor { var, start, limit, step, body } => {
                writeln!(out, "{pad}for {var} = {start}, {limit}, {step} do").unwrap();
                for s in body { s.emit(out, indent + 1); }
                writeln!(out, "{pad}end").unwrap();
            }
            Self::GenericFor { vars, iters, body } => {
                let vs = vars.join(", ");
                let is: Vec<String> = iters.iter().map(|e| format!("{e}")).collect();
                writeln!(out, "{pad}for {vs} in {} do", is.join(", ")).unwrap();
                for s in body { s.emit(out, indent + 1); }
                writeln!(out, "{pad}end").unwrap();
            }
            Self::If { cond, then_body, else_body } => {
                writeln!(out, "{pad}if {cond} then").unwrap();
                for s in then_body { s.emit(out, indent + 1); }
                if !else_body.is_empty() {
                    writeln!(out, "{pad}else").unwrap();
                    for s in else_body { s.emit(out, indent + 1); }
                }
                writeln!(out, "{pad}end").unwrap();
            }
            Self::Return(vals) => {
                if vals.is_empty() {
                    writeln!(out, "{pad}return").unwrap();
                } else {
                    let vs: Vec<String> = vals.iter().map(|e| format!("{e}")).collect();
                    writeln!(out, "{pad}return {}", vs.join(", ")).unwrap();
                }
            }
            Self::UpvalueClose(_) => {}
            Self::Comment(c) => writeln!(out, "{pad}-- {c}").unwrap(),
        }
    }
}

impl fmt::Display for LjStmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        self.emit(&mut s, 0);
        write!(f, "{}", s.trim_end())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ExprTree â€“ per-proto expression state during decompilation
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Tracks the live expression for each register slot during the dataflow scan.
#[derive(Debug, Clone)]
pub struct ExprTree {
    /// slot -> current expression
    slots: HashMap<u8, LjExpr>,
    /// slot -> local name (from debug info)
    local_names: HashMap<u8, String>,
    /// upvalue index -> name
    upvalue_names: HashMap<u8, String>,
}

impl ExprTree {
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
            local_names: HashMap::new(),
            upvalue_names: HashMap::new(),
        }
    }

    /// Assign debug names from proto info.
    pub fn apply_debug_names(&mut self, proto: &LjProto) {
        for (i, name) in proto.upvalue_names.iter().enumerate() {
            if !name.is_empty() {
                self.upvalue_names.insert(u8::try_from(i).unwrap_or(u8::MAX), name.clone());
            }
        }
        for lv in &proto.local_vars {
            if !lv.name.is_empty() && !lv.name.starts_with('(') {
                // map start slot heuristically: just record the name
                // We use slot = start_pc mod frame_size as a best-effort
                let slot = u8::try_from(lv.start_pc % u32::from(proto.frame_size).max(1)).unwrap_or(u8::MAX);
                self.local_names.entry(slot).or_insert_with(|| lv.name.clone());
            }
        }
    }

    pub fn set(&mut self, slot: u8, expr: LjExpr) {
        self.slots.insert(slot, expr);
    }

    #[must_use]
    pub fn get(&self, slot: u8) -> LjExpr {
        if let Some(name) = self.local_names.get(&slot) {
            return LjExpr::Local(name.clone());
        }
        self.slots.get(&slot).cloned().unwrap_or(LjExpr::Slot(slot))
    }

    #[must_use]
    pub fn uv_name(&self, idx: u8) -> Option<String> {
        self.upvalue_names.get(&idx).cloned()
    }
}

impl Default for ExprTree {
    fn default() -> Self { Self::new() }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// DecompResult
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Result of decompiling one `LjProto`.
#[derive(Debug, Clone)]
pub struct DecompResult {
    /// Proto index this result corresponds to.
    pub proto_index: usize,
    /// Deduced function name (from debug or proto chain, may be empty).
    pub name: String,
    /// Whether this proto is a vararg function.
    pub is_vararg: bool,
    /// Number of fixed parameters.
    pub num_params: u8,
    /// Top-level statement list.
    pub stmts: Vec<LjStmt>,
    /// Child proto results (nested functions).
    pub children: Vec<Self>,
    /// Warnings or notes generated during decompilation.
    pub warnings: Vec<String>,
}

impl DecompResult {
    /// Render this proto's body as Lua source.
    #[must_use]
    pub fn to_source(&self, header: bool) -> String {
        let mut out = String::new();
        if header {
            let params: Vec<String> = (0..self.num_params)
                .map(|i| format!("a{i}"))
                .collect();
            let varg = if self.is_vararg { if params.is_empty() { "..." } else { ", ..." } } else { "" };
            let fname = if self.name.is_empty() { "func".to_string() } else { self.name.clone() };
            writeln!(out, "function {fname}({}{varg})", params.join(", ")).unwrap();
            for s in &self.stmts { s.emit(&mut out, 1); }
            out.push_str("end\n");
        } else {
            for s in &self.stmts { s.emit(&mut out, 0); }
        }
        out
    }
}

impl fmt::Display for DecompResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_source(true))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LjDecompiler
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Decompiles a list of `LjProto` instances back to Lua source.
///
/// Algorithm:
/// 1. For each proto, decode all instructions with `LjInstrDecoder`.
/// 2. Identify basic block boundaries from branch targets.
/// 3. Walk instructions in order, maintaining an `ExprTree` for register
///    expressions and emitting `LjStmt` nodes when a side-effecting opcode
///    is encountered.
/// 4. Reconstruct simple control flow (if/while/for) by pattern-matching
///    canonical instruction sequences.
pub struct LjDecompiler {
    /// All protos from the bytecode chunk.
    protos: Vec<LjProto>,
    /// Total number of instruction words decoded across every `decompile_proto`
    /// call. Exposed via [`Self::decoded_words`].
    decoded_words: usize,
    /// Child-proto-index -> parent slot that holds the closure.
    closure_map: HashMap<u32, u8>,
}

impl LjDecompiler {
    /// Number of instruction words this decompiler has decoded so far across
    /// all calls to `decompile_proto` / `decompile_all`.
    #[must_use]
    pub const fn decoded_words(&self) -> usize {
        self.decoded_words
    }

    /// Read-only view of the closure slot map populated during decompilation.
    #[must_use]
    pub const fn closure_map(&self) -> &HashMap<u32, u8> {
        &self.closure_map
    }

    /// All parsed protos, in the order produced by the parser.
    #[must_use]
    pub fn protos(&self) -> &[LjProto] {
        &self.protos
    }
}

impl fmt::Debug for LjDecompiler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LjDecompiler({} protos)", self.protos.len())
    }
}

impl LjDecompiler {
    /// Create a new decompiler from a vector of parsed protos.
    #[must_use]
    pub fn new(protos: Vec<LjProto>) -> Self {
        Self {
            protos,
            decoded_words: 0,
            closure_map: HashMap::new(),
        }
    }

    /// Decompile all protos and return results in order (outermost first).
    pub fn decompile_all(&mut self) -> Vec<DecompResult> {
        let count = self.protos.len();
        (0..count).map(|i| self.decompile_proto(i)).collect()
    }

    /// Decompile the top-level (last) proto, which is the script body.
    pub fn decompile_top(&mut self) -> Option<DecompResult> {
        let n = self.protos.len();
        if n == 0 { return None; }
        Some(self.decompile_proto(n - 1))
    }

    /// Decompile proto at `index`.
    pub fn decompile_proto(&mut self, index: usize) -> DecompResult {
        if index >= self.protos.len() {
            return DecompResult {
                proto_index: index,
                name: String::new(),
                is_vararg: false,
                num_params: 0,
                stmts: vec![LjStmt::Comment(format!("invalid proto index {index}"))],
                children: Vec::new(),
                warnings: Vec::new(),
            };
        }
        let proto = self.protos[index].clone();
        let words: Vec<u32> = proto.instructions.iter().map(|i| i.word).collect();
        self.decoded_words += words.len();
        let mut decoder = LjInstrDecoder::new(&words);
        let instrs = decoder.decode_all();
        let _branch_targets: HashSet<u32> = decoder.branch_targets().into_iter().collect();

        let mut tree = ExprTree::new();
        tree.apply_debug_names(&proto);

        let mut stmts: Vec<LjStmt> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut child_results: Vec<DecompResult> = Vec::new();
        let mut i = 0usize;

        while i < instrs.len() {
            let instr = &instrs[i];
            match instr.opcode {
                // â”€â”€ Skip function headers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                op if op.is_func_header() => {}

                // â”€â”€ Constant loads â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::KNIL => {
                    let end = instr.d as u8;
                    for s in instr.a..=end {
                        tree.set(s, LjExpr::Nil);
                    }
                    let names: Vec<String> = (instr.a..=end).map(|s| format!("v{s}")).collect();
                    stmts.push(LjStmt::Local(names, vec![]));
                }
                LjOpcode::KPRI => {
                    let e = match instr.d {
                        0 => LjExpr::Nil,
                        1 => LjExpr::Bool(false),
                        _ => LjExpr::Bool(true),
                    };
                    tree.set(instr.a, e);
                }
                LjOpcode::KSHORT => {
                    let e = LjExpr::Int(i64::from(instr.clone().d_signed()));
                    tree.set(instr.a, e);
                }
                LjOpcode::KNUM => {
                    let e = if let Some(c) = proto.kn.get(instr.d as usize) {
                        match c {
                            LjConst::Int(n) => LjExpr::Int(i64::from(*n)),
                            LjConst::Float(v) => LjExpr::Float(*v),
                            _ => LjExpr::Raw(format!("kn[{}]", instr.d)),
                        }
                    } else {
                        LjExpr::Raw(format!("kn[{}]", instr.d))
                    };
                    tree.set(instr.a, e);
                }
                LjOpcode::KSTR => {
                    let e = if let Some(LjConst::Str(s)) = proto.kgc.get(instr.d as usize) {
                        LjExpr::Str(s.clone())
                    } else {
                        LjExpr::Raw(format!("kstr[{}]", instr.d))
                    };
                    tree.set(instr.a, e);
                }

                // â”€â”€ Moves â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::MOV => {
                    let e = tree.get(instr.d as u8);
                    tree.set(instr.a, e);
                }

                // â”€â”€ Unary ops â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::NOT => {
                    let e = LjExpr::Unop(UnopKind::Not, Box::new(tree.get(instr.d as u8)));
                    tree.set(instr.a, e);
                }
                LjOpcode::UNM => {
                    let e = LjExpr::Unop(UnopKind::Neg, Box::new(tree.get(instr.d as u8)));
                    tree.set(instr.a, e);
                }
                LjOpcode::LEN => {
                    let e = LjExpr::Unop(UnopKind::Len, Box::new(tree.get(instr.d as u8)));
                    tree.set(instr.a, e);
                }

                // â”€â”€ Binary ops â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                op @ (LjOpcode::ADDVV | LjOpcode::SUBVV | LjOpcode::MULVV
                    | LjOpcode::DIVVV | LjOpcode::MODVV | LjOpcode::POW | LjOpcode::CAT) => {
                    let kind = match op {
                        LjOpcode::ADDVV => BinopKind::Add, LjOpcode::SUBVV => BinopKind::Sub,
                        LjOpcode::MULVV => BinopKind::Mul, LjOpcode::DIVVV => BinopKind::Div,
                        LjOpcode::MODVV => BinopKind::Mod, LjOpcode::POW   => BinopKind::Pow,
                        _               => BinopKind::Cat,
                    };
                    let l = tree.get(instr.b);
                    let r = tree.get(instr.c);
                    tree.set(instr.a, LjExpr::Binop(kind, Box::new(l), Box::new(r)));
                }
                op @ (LjOpcode::ADDVN | LjOpcode::SUBVN | LjOpcode::MULVN
                    | LjOpcode::DIVVN | LjOpcode::MODVN) => {
                    let kind = match op {
                        LjOpcode::ADDVN => BinopKind::Add, LjOpcode::SUBVN => BinopKind::Sub,
                        LjOpcode::MULVN => BinopKind::Mul, LjOpcode::DIVVN => BinopKind::Div,
                        _               => BinopKind::Mod,
                    };
                    let l = tree.get(instr.b);
                    let r = proto.kn.get(instr.c as usize).map_or_else(|| LjExpr::Raw(format!("kn[{}]", instr.c)), |c| match c {
                            LjConst::Int(n) => LjExpr::Int(i64::from(*n)),
                            LjConst::Float(v) => LjExpr::Float(*v),
                            _ => LjExpr::Raw(format!("kn[{}]", instr.c)),
                        });
                    tree.set(instr.a, LjExpr::Binop(kind, Box::new(l), Box::new(r)));
                }
                op @ (LjOpcode::ADDNV | LjOpcode::SUBNV | LjOpcode::MULNV
                    | LjOpcode::DIVNV | LjOpcode::MODNV) => {
                    let kind = match op {
                        LjOpcode::ADDNV => BinopKind::Add, LjOpcode::SUBNV => BinopKind::Sub,
                        LjOpcode::MULNV => BinopKind::Mul, LjOpcode::DIVNV => BinopKind::Div,
                        _               => BinopKind::Mod,
                    };
                    let l = proto.kn.get(instr.c as usize).map_or_else(|| LjExpr::Raw(format!("kn[{}]", instr.c)), |c| match c {
                            LjConst::Int(n) => LjExpr::Int(i64::from(*n)),
                            LjConst::Float(v) => LjExpr::Float(*v),
                            _ => LjExpr::Raw(format!("kn[{}]", instr.c)),
                        });
                    let r = tree.get(instr.b);
                    tree.set(instr.a, LjExpr::Binop(kind, Box::new(l), Box::new(r)));
                }

                // â”€â”€ Global access â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::GGET => {
                    let name = if let Some(LjConst::Str(s)) = proto.kgc.get(instr.d as usize) {
                        s.clone()
                    } else { format!("g{}", instr.d) };
                    tree.set(instr.a, LjExpr::Global(name));
                }
                LjOpcode::GSET => {
                    let name = if let Some(LjConst::Str(s)) = proto.kgc.get(instr.d as usize) {
                        s.clone()
                    } else { format!("g{}", instr.d) };
                    stmts.push(LjStmt::Assign(vec![LjExpr::Global(name)], vec![tree.get(instr.a)]));
                }

                // â”€â”€ Table access â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::TGETV => {
                    let t = tree.get(instr.b); let k = tree.get(instr.c);
                    tree.set(instr.a, LjExpr::Index(Box::new(t), Box::new(k)));
                }
                LjOpcode::TGETS => {
                    let t = tree.get(instr.b);
                    let key = if let Some(LjConst::Str(s)) = proto.kgc.get(instr.c as usize) {
                        s.clone()
                    } else { format!("f{}", instr.c) };
                    tree.set(instr.a, LjExpr::Field(Box::new(t), key));
                }
                LjOpcode::TGETB => {
                    let t = tree.get(instr.b);
                    tree.set(instr.a, LjExpr::Index(Box::new(t), Box::new(LjExpr::Int(i64::from(instr.c)))));
                }
                LjOpcode::TSETV => {
                    let t = tree.get(instr.b); let k = tree.get(instr.c); let v = tree.get(instr.a);
                    stmts.push(LjStmt::Assign(vec![LjExpr::Index(Box::new(t), Box::new(k))], vec![v]));
                }
                LjOpcode::TSETS => {
                    let t = tree.get(instr.b);
                    let key = if let Some(LjConst::Str(s)) = proto.kgc.get(instr.c as usize) {
                        s.clone()
                    } else { format!("f{}", instr.c) };
                    let v = tree.get(instr.a);
                    stmts.push(LjStmt::Assign(vec![LjExpr::Field(Box::new(t), key)], vec![v]));
                }
                LjOpcode::TSETB => {
                    let t = tree.get(instr.b);
                    let v = tree.get(instr.a);
                    stmts.push(LjStmt::Assign(
                        vec![LjExpr::Index(Box::new(t), Box::new(LjExpr::Int(i64::from(instr.c))))],
                        vec![v],
                    ));
                }
                LjOpcode::TNEW => {
                    tree.set(instr.a, LjExpr::Table(Vec::new()));
                }
                LjOpcode::TDUP => {
                    tree.set(instr.a, LjExpr::Table(Vec::new()));
                }

                // â”€â”€ Upvalues â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::UGET => {
                    let name = tree.uv_name(instr.d as u8);
                    tree.set(instr.a, LjExpr::Upvalue(instr.d as u8, name));
                }
                LjOpcode::USETV => {
                    let name = tree.uv_name(instr.a);
                    let target = LjExpr::Upvalue(instr.a, name);
                    stmts.push(LjStmt::Assign(vec![target], vec![tree.get(instr.d as u8)]));
                }
                LjOpcode::UCLO => {
                    stmts.push(LjStmt::UpvalueClose(instr.a));
                }

                // â”€â”€ Closures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::FNEW => {
                    let child_idx = u32::from(instr.d);
                    tree.set(instr.a, LjExpr::Closure(child_idx));
                    self.closure_map.insert(child_idx, instr.a);
                    if (child_idx as usize) < self.protos.len() {
                        let child = self.decompile_proto(child_idx as usize);
                        child_results.push(child);
                    }
                }

                // â”€â”€ Calls â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::CALL => {
                    let callee = tree.get(instr.a);
                    let nargs = (instr.c as usize).saturating_sub(1);
                    let args: Vec<LjExpr> = (1..=nargs).map(|j| tree.get(instr.a + j as u8)).collect();
                    let call_expr = LjExpr::Call(Box::new(callee), args);
                    let nret = (instr.b as usize).saturating_sub(1);
                    if nret == 0 {
                        stmts.push(LjStmt::Call(call_expr));
                    } else {
                        let targets: Vec<LjExpr> = (0..nret).map(|j| LjExpr::Slot(instr.a + j as u8)).collect();
                        for j in 0..nret { tree.set(instr.a + j as u8, LjExpr::Raw(format!("ret{j}"))); }
                        stmts.push(LjStmt::Assign(targets, vec![call_expr]));
                    }
                }
                LjOpcode::CALLM => {
                    let callee = tree.get(instr.a);
                    let nargs = instr.c as usize;
                    let args: Vec<LjExpr> = (1..=nargs).map(|j| tree.get(instr.a + j as u8)).collect();
                    stmts.push(LjStmt::Call(LjExpr::Call(Box::new(callee), args)));
                }
                LjOpcode::CALLT | LjOpcode::CALLMT => {
                    let callee = tree.get(instr.a);
                    let nargs = (instr.d as usize).saturating_sub(1);
                    let args: Vec<LjExpr> = (1..=nargs).map(|j| tree.get(instr.a + j as u8)).collect();
                    stmts.push(LjStmt::Return(vec![LjExpr::Call(Box::new(callee), args)]));
                }

                // â”€â”€ Returns â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::RET0 => stmts.push(LjStmt::Return(vec![])),
                LjOpcode::RET1 => stmts.push(LjStmt::Return(vec![tree.get(instr.a)])),
                LjOpcode::RET => {
                    let n = (instr.d as usize).saturating_sub(2);
                    let vals: Vec<LjExpr> = (0..=n).map(|j| tree.get(instr.a + j as u8)).collect();
                    stmts.push(LjStmt::Return(vals));
                }
                LjOpcode::RETM => {
                    let vals = vec![LjExpr::Vararg];
                    stmts.push(LjStmt::Return(vals));
                }

                // â”€â”€ Vararg â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::VARG => {
                    tree.set(instr.a, LjExpr::Vararg);
                }

                // â”€â”€ Unconditional jump (skip/loop back-edge) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::JMP => {
                    // Emit as comment in flat mode; CFG reconstruction handles loops
                    stmts.push(LjStmt::Comment(format!("jmp -> PC {}", {
                        let d = instr.d;
                        let pc = instr.pc;
                        (i64::from(pc) + 1 + i64::from(d) - 0x8000) as u32
                    })));
                }

                // â”€â”€ For loops (emit flat skeleton) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                LjOpcode::FORI | LjOpcode::JFORI => {
                    let base = instr.a;
                    let start = tree.get(base);
                    let limit = tree.get(base + 1);
                    let step  = tree.get(base + 2);
                    let var   = format!("i{}", base + 3);
                    stmts.push(LjStmt::NumericFor {
                        var,
                        start,
                        limit,
                        step,
                        body: Vec::new(),
                    });
                }
                LjOpcode::ITERC | LjOpcode::ITERN => {
                    let base = instr.a;
                    let iter  = tree.get(base - 3);
                    let state = tree.get(base - 2);
                    let ctrl  = tree.get(base - 1);
                    let nvars = instr.b as usize;
                    let vars: Vec<String> = (0..nvars).map(|j| format!("k{}", base + j as u8)).collect();
                    stmts.push(LjStmt::GenericFor {
                        vars,
                        iters: vec![iter, state, ctrl],
                        body: Vec::new(),
                    });
                }

                // â”€â”€ Comparison + implied JMP pattern â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                op if op.is_branch() => {
                    stmts.push(LjStmt::Comment(format!("{} (branch)", op.name())));
                }

                _ => {
                    warnings.push(format!("unhandled opcode {} at PC {}", instr.opcode, instr.pc));
                    stmts.push(LjStmt::Comment(format!("{instr}")));
                }
            }
            i += 1;
        }

        let is_vararg = (proto.flags & 0x02) != 0;
        DecompResult {
            proto_index: index,
            name: proto.source_name.clone().unwrap_or_default(),
            is_vararg,
            num_params: proto.num_params,
            stmts,
            children: child_results,
            warnings,
        }
    }

    /// Return the number of protos this decompiler holds.
    #[must_use]
    pub const fn proto_count(&self) -> usize {
        self.protos.len()
    }

    /// Render all protos as a single Lua source string.
    pub fn render_all(&mut self) -> String {
        let results = self.decompile_all();
        let mut out = String::new();
        for r in &results {
            out.push_str(&r.to_source(true));
            out.push('\n');
        }
        out
    }
}

