//! WebAssembly → pseudo-C AST decompiler.
//!
//! Converts a sequence of decoded Wasm instructions into a high-level AST
//! and renders it.  Covers:
//! - `WasmAst` — expression and statement nodes
//! - `WasmDecompiler` — top-level entry point
//! - `FunctionDecompiler` — per-function decompilation
//! - `LocalVarNaming` — names local variables
//! - `ControlFlowRecovery` — turns structured control-flow back into statements
//! - `ExpressionBuilder` — value-stack → expression tree
//! - `WasmPrinter` — renders the AST to a string

use crate::{WasmValueType, read_uleb128};
use rustre_core::errors::CoreError;
use std::fmt;

// ── WasmAst — Expression nodes ────────────────────────────────────────────────

/// A Wasm expression node.
#[derive(Debug, Clone, PartialEq)]
pub enum WasmExpr {
    /// Integer constant.
    I32Const(i32),
    /// 64-bit integer constant.
    I64Const(i64),
    /// 32-bit float constant.
    F32Const(f32),
    /// 64-bit float constant.
    F64Const(f64),
    /// Local variable read.
    LocalGet { idx: u32, name: String },
    /// Global variable read.
    GlobalGet(u32),
    /// Pointer-sized memory load.
    Load {
        mem_op: String,
        addr: Box<WasmExpr>,
        offset: u64,
    },
    /// Binary arithmetic / comparison.
    BinOp {
        op: WasmBinOp,
        lhs: Box<WasmExpr>,
        rhs: Box<WasmExpr>,
    },
    /// Unary operation.
    UnaryOp {
        op: WasmUnaryOp,
        expr: Box<WasmExpr>,
    },
    /// Convert / wrap / extend / trunc.
    Convert { op: String, expr: Box<WasmExpr> },
    /// Function call: `func_idx(args)`.
    Call { func_idx: u32, args: Vec<WasmExpr> },
    /// Indirect call: `table[type_idx](args)`.
    CallIndirect { type_idx: u32, args: Vec<WasmExpr> },
    /// Select: `cond ? a : b`.
    Select {
        cond: Box<WasmExpr>,
        a: Box<WasmExpr>,
        b: Box<WasmExpr>,
    },
    /// Drop result.
    Drop(Box<WasmExpr>),
    /// Memory size.
    MemorySize,
    /// Memory grow.
    MemoryGrow(Box<WasmExpr>),
    /// Unreachable placeholder.
    Unreachable,
}

impl fmt::Display for WasmExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I32Const(v) => write!(f, "{v}"),
            Self::I64Const(v) => write!(f, "{v}LL"),
            Self::F32Const(v) => write!(f, "{v}f"),
            Self::F64Const(v) => write!(f, "{v}"),
            Self::LocalGet { name, .. } => write!(f, "{name}"),
            Self::GlobalGet(i) => write!(f, "global[{i}]"),
            Self::Load {
                mem_op,
                addr,
                offset,
            } => {
                if *offset == 0 {
                    write!(f, "{mem_op}({addr})")
                } else {
                    write!(f, "{mem_op}({addr}+{offset})")
                }
            }
            Self::BinOp { op, lhs, rhs } => write!(f, "({lhs} {op} {rhs})"),
            Self::UnaryOp { op, expr } => write!(f, "{op}{expr}"),
            Self::Convert { op, expr } => write!(f, "{op}({expr})"),
            Self::Call { func_idx, args } => {
                write!(f, "func_{func_idx}(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            Self::CallIndirect { type_idx, args } => {
                write!(f, "call_indirect<{type_idx}>(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            Self::Select { cond, a, b } => write!(f, "({cond} ? {a} : {b})"),
            Self::Drop(e) => write!(f, "(void){e}"),
            Self::MemorySize => write!(f, "memory.size()"),
            Self::MemoryGrow(e) => write!(f, "memory.grow({e})"),
            Self::Unreachable => write!(f, "unreachable!()"),
        }
    }
}

/// Binary operator for Wasm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmBinOp {
    Add,
    Sub,
    Mul,
    DivS,
    DivU,
    RemS,
    RemU,
    And,
    Or,
    Xor,
    Shl,
    ShrS,
    ShrU,
    Rotl,
    Rotr,
    Eq,
    Ne,
    LtS,
    LtU,
    GtS,
    GtU,
    LeS,
    LeU,
    GeS,
    GeU,
    FAdd,
    FSub,
    FMul,
    FDiv,
    FMin,
    FMax,
    FEq,
    FNe,
    FLt,
    FGt,
    FLe,
    FGe,
}

impl fmt::Display for WasmBinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::DivS | Self::DivU => "/",
            Self::RemS | Self::RemU => "%",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::ShrS | Self::ShrU => ">>",
            Self::Rotl => "rotl",
            Self::Rotr => "rotr",
            Self::Eq | Self::FEq => "==",
            Self::Ne | Self::FNe => "!=",
            Self::LtS | Self::LtU | Self::FLt => "<",
            Self::GtS | Self::GtU | Self::FGt => ">",
            Self::LeS | Self::LeU | Self::FLe => "<=",
            Self::GeS | Self::GeU | Self::FGe => ">=",
            Self::FAdd => "+",
            Self::FSub => "-",
            Self::FMul => "*",
            Self::FDiv => "/",
            Self::FMin => "min",
            Self::FMax => "max",
        };
        write!(f, "{s}")
    }
}

/// Unary operator for Wasm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmUnaryOp {
    Neg,
    Eqz,
    Clz,
    Ctz,
    Popcnt,
    Abs,
    Sqrt,
    Ceil,
    Floor,
    Trunc,
    Nearest,
}

impl fmt::Display for WasmUnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Neg => "-",
            Self::Eqz => "!",
            Self::Clz => "clz",
            Self::Ctz => "ctz",
            Self::Popcnt => "popcnt",
            Self::Abs => "fabs",
            Self::Sqrt => "sqrt",
            Self::Ceil => "ceil",
            Self::Floor => "floor",
            Self::Trunc => "trunc",
            Self::Nearest => "nearest",
        };
        write!(f, "{s}")
    }
}

// ── WasmStmt — Statement nodes ────────────────────────────────────────────────

/// A Wasm statement node.
#[derive(Debug, Clone, PartialEq)]
pub enum WasmStmt {
    /// Local variable write.
    LocalSet {
        idx: u32,
        name: String,
        value: WasmExpr,
    },
    /// Global variable write.
    GlobalSet { idx: u32, value: WasmExpr },
    /// Memory store.
    Store {
        mem_op: String,
        addr: WasmExpr,
        value: WasmExpr,
        offset: u64,
    },
    /// Expression statement (call with dropped result).
    ExprStmt(WasmExpr),
    /// `if (cond) { then } else { else_ }`.
    If {
        cond: WasmExpr,
        then: Vec<WasmStmt>,
        else_: Vec<WasmStmt>,
    },
    /// `while (cond) { body }`.
    While { cond: WasmExpr, body: Vec<WasmStmt> },
    /// `loop { body }` — loop block (may break/continue).
    Loop(Vec<WasmStmt>),
    /// `break N;` — break with label depth.
    Break(u32),
    /// `return value;`.
    Return(Option<WasmExpr>),
    /// Unreachable.
    Unreachable,
    /// Block comment.
    Comment(String),
}

impl fmt::Display for WasmStmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalSet { name, value, .. } => writeln!(f, "{name} = {value};"),
            Self::GlobalSet { idx, value } => writeln!(f, "global[{idx}] = {value};"),
            Self::Store {
                mem_op,
                addr,
                value,
                offset,
            } => {
                if *offset == 0 {
                    writeln!(f, "{mem_op}_store({addr}) = {value};")
                } else {
                    writeln!(f, "{mem_op}_store({addr}+{offset}) = {value};")
                }
            }
            Self::ExprStmt(e) => writeln!(f, "{e};"),
            Self::Return(None) => writeln!(f, "return;"),
            Self::Return(Some(e)) => writeln!(f, "return {e};"),
            Self::Break(n) => writeln!(f, "break /*depth={n}*/;"),
            Self::Unreachable => writeln!(f, "unreachable!();"),
            Self::Comment(s) => writeln!(f, "// {s}"),
            _ => writeln!(f, "/* stmt */"),
        }
    }
}

// ── LocalVarNaming ────────────────────────────────────────────────────────────

/// Assigns human-readable names to local variables.
#[derive(Debug, Clone)]
pub struct LocalVarNaming {
    names: Vec<String>,
    types: Vec<WasmValueType>,
}

impl LocalVarNaming {
    /// Create naming with `n` locals of `default_type`.
    #[must_use]
    pub fn new(n: usize, default_type: WasmValueType) -> Self {
        let names = (0..n).map(|i| format!("v{i}")).collect();
        let types = vec![default_type; n];
        Self { names, types }
    }

    /// Set a custom name for local `idx`.
    pub fn set_name(&mut self, idx: usize, name: String) {
        if idx < self.names.len() {
            self.names[idx] = name;
        }
    }

    /// Get the name for local `idx`.
    #[must_use]
    pub fn name(&self, idx: u32) -> String {
        self.names
            .get(idx as usize)
            .cloned()
            .unwrap_or_else(|| format!("v{idx}"))
    }

    /// Get the value type for local `idx`.
    #[must_use]
    pub fn value_type(&self, idx: u32) -> WasmValueType {
        self.types
            .get(idx as usize)
            .copied()
            .unwrap_or(WasmValueType::I32)
    }

    /// Count of local variables.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.names.len()
    }

    /// Generate a C-style declaration for local `idx`.
    #[must_use]
    pub fn declaration(&self, idx: u32) -> String {
        let ty = self.value_type(idx).name();
        let name = self.name(idx);
        format!("{ty} {name};")
    }
}

// ── ControlFlowRecovery ───────────────────────────────────────────────────────

/// Converts structured Wasm blocks/loops into higher-level statements.
pub struct ControlFlowRecovery {
    pub stmts: Vec<WasmStmt>,
    block_stack: Vec<BlockKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Block,
    Loop,
    If,
}

impl ControlFlowRecovery {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stmts: Vec::new(),
            block_stack: Vec::new(),
        }
    }

    /// Enter a block context.
    pub fn enter_block(&mut self) {
        self.block_stack.push(BlockKind::Block);
    }
    /// Enter a loop context.
    pub fn enter_loop(&mut self) {
        self.block_stack.push(BlockKind::Loop);
    }
    /// Enter an if context.
    pub fn enter_if(&mut self) {
        self.block_stack.push(BlockKind::If);
    }

    /// Exit the innermost block/loop/if.
    pub fn exit(&mut self) {
        self.block_stack.pop();
    }

    /// Current nesting depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.block_stack.len()
    }

    /// Emit a break statement at depth `n`.
    pub fn emit_break(&mut self, n: u32) {
        self.stmts.push(WasmStmt::Break(n));
    }

    /// Emit a return statement.
    pub fn emit_return(&mut self, val: Option<WasmExpr>) {
        self.stmts.push(WasmStmt::Return(val));
    }

    /// Emit a raw statement.
    pub fn emit(&mut self, stmt: WasmStmt) {
        self.stmts.push(stmt);
    }

    /// Take the accumulated statements.
    #[must_use]
    pub fn take_stmts(&mut self) -> Vec<WasmStmt> {
        std::mem::take(&mut self.stmts)
    }
}

impl Default for ControlFlowRecovery {
    fn default() -> Self {
        Self::new()
    }
}

// ── ExpressionBuilder ─────────────────────────────────────────────────────────

/// Builds Wasm expression trees from the value stack.
pub struct ExpressionBuilder {
    stack: Vec<WasmExpr>,
    locals: LocalVarNaming,
}

impl ExpressionBuilder {
    #[must_use]
    pub const fn new(locals: LocalVarNaming) -> Self {
        Self {
            stack: Vec::new(),
            locals,
        }
    }

    pub fn push(&mut self, e: WasmExpr) {
        self.stack.push(e);
    }

    pub fn pop(&mut self) -> Option<WasmExpr> {
        self.stack.pop()
    }

    #[must_use]
    pub const fn depth(&self) -> usize {
        self.stack.len()
    }

    fn pop2(&mut self) -> Option<(WasmExpr, WasmExpr)> {
        let rhs = self.stack.pop()?;
        let lhs = self.stack.pop()?;
        Some((lhs, rhs))
    }

    fn bin(&mut self, op: WasmBinOp) -> Option<WasmExpr> {
        let (lhs, rhs) = self.pop2()?;
        Some(WasmExpr::BinOp {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        })
    }

    fn unary(&mut self, op: WasmUnaryOp) -> Option<WasmExpr> {
        let e = self.stack.pop()?;
        Some(WasmExpr::UnaryOp {
            op,
            expr: Box::new(e),
        })
    }

    /// Process one mnemonic and produce optional statement.
    pub fn process(&mut self, mnemonic: &str, operands: &str) -> Option<WasmStmt> {
        match mnemonic {
            "unreachable" => {
                self.push(WasmExpr::Unreachable);
                None
            }
            "nop" => None,
            "i32.const" => {
                let v = operands.parse::<i32>().unwrap_or(0);
                self.push(WasmExpr::I32Const(v));
                None
            }
            "i64.const" => {
                let v = operands.parse::<i64>().unwrap_or(0);
                self.push(WasmExpr::I64Const(v));
                None
            }
            "local.get" => {
                let idx = operands.parse::<u32>().unwrap_or(0);
                let name = self.locals.name(idx);
                self.push(WasmExpr::LocalGet { idx, name });
                None
            }
            "local.set" => {
                let idx = operands.parse::<u32>().unwrap_or(0);
                let name = self.locals.name(idx);
                let value = self.pop()?;
                Some(WasmStmt::LocalSet { idx, name, value })
            }
            "local.tee" => {
                let idx = operands.parse::<u32>().unwrap_or(0);
                let name = self.locals.name(idx);
                let value = self.stack.last()?.clone();
                Some(WasmStmt::LocalSet { idx, name, value })
            }
            "global.get" => {
                let idx = operands.parse::<u32>().unwrap_or(0);
                self.push(WasmExpr::GlobalGet(idx));
                None
            }
            "global.set" => {
                let idx = operands.parse::<u32>().unwrap_or(0);
                let value = self.pop()?;
                Some(WasmStmt::GlobalSet { idx, value })
            }
            "i32.add" => {
                let e = self.bin(WasmBinOp::Add)?;
                self.push(e);
                None
            }
            "i32.sub" => {
                let e = self.bin(WasmBinOp::Sub)?;
                self.push(e);
                None
            }
            "i32.mul" => {
                let e = self.bin(WasmBinOp::Mul)?;
                self.push(e);
                None
            }
            "i32.div_s" => {
                let e = self.bin(WasmBinOp::DivS)?;
                self.push(e);
                None
            }
            "i32.div_u" => {
                let e = self.bin(WasmBinOp::DivU)?;
                self.push(e);
                None
            }
            "i32.and" => {
                let e = self.bin(WasmBinOp::And)?;
                self.push(e);
                None
            }
            "i32.or" => {
                let e = self.bin(WasmBinOp::Or)?;
                self.push(e);
                None
            }
            "i32.xor" => {
                let e = self.bin(WasmBinOp::Xor)?;
                self.push(e);
                None
            }
            "i32.shl" => {
                let e = self.bin(WasmBinOp::Shl)?;
                self.push(e);
                None
            }
            "i32.shr_s" => {
                let e = self.bin(WasmBinOp::ShrS)?;
                self.push(e);
                None
            }
            "i32.shr_u" => {
                let e = self.bin(WasmBinOp::ShrU)?;
                self.push(e);
                None
            }
            "i64.add" => {
                let e = self.bin(WasmBinOp::Add)?;
                self.push(e);
                None
            }
            "i64.mul" => {
                let e = self.bin(WasmBinOp::Mul)?;
                self.push(e);
                None
            }
            "f32.add" => {
                let e = self.bin(WasmBinOp::FAdd)?;
                self.push(e);
                None
            }
            "f64.add" => {
                let e = self.bin(WasmBinOp::FAdd)?;
                self.push(e);
                None
            }
            "i32.eq" => {
                let e = self.bin(WasmBinOp::Eq)?;
                self.push(e);
                None
            }
            "i32.ne" => {
                let e = self.bin(WasmBinOp::Ne)?;
                self.push(e);
                None
            }
            "i32.lt_s" => {
                let e = self.bin(WasmBinOp::LtS)?;
                self.push(e);
                None
            }
            "i32.gt_s" => {
                let e = self.bin(WasmBinOp::GtS)?;
                self.push(e);
                None
            }
            "i32.eqz" => {
                let e = self.unary(WasmUnaryOp::Eqz)?;
                self.push(e);
                None
            }
            "i64.eqz" => {
                let e = self.unary(WasmUnaryOp::Eqz)?;
                self.push(e);
                None
            }
            "drop" => {
                self.pop();
                None
            }
            "return" => {
                let v = self.pop();
                Some(WasmStmt::Return(v))
            }
            "i32.load" => {
                let addr = self.pop()?;
                let offset = parse_offset(operands);
                self.push(WasmExpr::Load {
                    mem_op: "i32.load".to_string(),
                    addr: Box::new(addr),
                    offset,
                });
                None
            }
            "i32.store" => {
                let value = self.pop()?;
                let addr = self.pop()?;
                let offset = parse_offset(operands);
                Some(WasmStmt::Store {
                    mem_op: "i32.store".to_string(),
                    addr,
                    value,
                    offset,
                })
            }
            "memory.size" => {
                self.push(WasmExpr::MemorySize);
                None
            }
            "memory.grow" => {
                let e = self.pop().unwrap_or(WasmExpr::I32Const(0));
                self.push(WasmExpr::MemoryGrow(Box::new(e)));
                None
            }
            "call" => {
                let idx = operands.parse::<u32>().unwrap_or(0);
                let e = WasmExpr::Call {
                    func_idx: idx,
                    args: Vec::new(),
                };
                self.push(e);
                None
            }
            "select" => {
                let cond = self.pop()?;
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(WasmExpr::Select {
                    cond: Box::new(cond),
                    a: Box::new(a),
                    b: Box::new(b),
                });
                None
            }
            _ => None,
        }
    }
}

fn parse_offset(operands: &str) -> u64 {
    // operands like "align=2 offset=8"
    operands
        .split_whitespace()
        .find(|s| s.starts_with("offset="))
        .and_then(|s| s.trim_start_matches("offset=").parse::<u64>().ok())
        .unwrap_or(0)
}

/// Decode a raw ULEB128 immediate from the start of `bytes`.
///
/// Convenience wrapper exposed for callers that hold the original bytecode
/// stream and want to recover the numeric value behind an operand string.
#[must_use]
pub fn decode_uleb128_immediate(bytes: &[u8]) -> Option<u64> {
    read_uleb128(bytes, 0).ok().map(|(v, _)| v)
}

// ── WasmTypeChecker ───────────────────────────────────────────────────────────

/// Lightweight type checker for Wasm expressions.
///
/// Tracks the value-stack type for each expression to detect type mismatches.
#[derive(Debug, Clone, Default)]
pub struct WasmTypeChecker {
    type_stack: Vec<WasmValueType>,
}

impl WasmTypeChecker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a type onto the type stack.
    pub fn push_type(&mut self, ty: WasmValueType) {
        self.type_stack.push(ty);
    }

    /// Pop a type from the type stack.
    pub fn pop_type(&mut self) -> Option<WasmValueType> {
        self.type_stack.pop()
    }

    /// Stack depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.type_stack.len()
    }

    /// Check that the top type matches `expected`.
    #[must_use]
    pub fn check_top(&self, expected: WasmValueType) -> bool {
        self.type_stack.last().copied() == Some(expected)
    }

    /// Clear the type stack.
    pub fn clear(&mut self) {
        self.type_stack.clear();
    }
}

// ── WasmFunctionSignature ─────────────────────────────────────────────────────

/// A Wasm function signature with parameter and result types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmFunctionSignature {
    pub params: Vec<WasmValueType>,
    pub results: Vec<WasmValueType>,
}

impl WasmFunctionSignature {
    /// Create a void → void signature.
    #[must_use]
    pub const fn void_void() -> Self {
        Self {
            params: vec![],
            results: vec![],
        }
    }

    /// Create an i32 → i32 signature.
    #[must_use]
    pub fn i32_to_i32() -> Self {
        Self {
            params: vec![WasmValueType::I32],
            results: vec![WasmValueType::I32],
        }
    }

    /// Return arity (`param_count`, `result_count`).
    #[must_use]
    pub const fn arity(&self) -> (usize, usize) {
        (self.params.len(), self.results.len())
    }

    /// Whether the function has any results.
    #[must_use]
    pub const fn has_results(&self) -> bool {
        !self.results.is_empty()
    }

    /// C-like signature string.
    #[must_use]
    pub fn c_string(&self) -> String {
        let params: Vec<_> = self.params.iter().map(|t| t.name()).collect();
        let results: Vec<_> = self.results.iter().map(|t| t.name()).collect();
        let ret = if results.is_empty() {
            "void".to_string()
        } else {
            results.join(", ")
        };
        format!("{ret}({})", params.join(", "))
    }
}

// ── WasmModuleInfo ────────────────────────────────────────────────────────────

/// High-level summary of a decompiled Wasm module.
#[derive(Debug, Clone, Default)]
pub struct WasmModuleInfo {
    pub function_count: u32,
    pub import_count: u32,
    pub export_count: u32,
    pub memory_pages: u32,
    pub has_start_function: bool,
    pub signatures: Vec<WasmFunctionSignature>,
}

impl WasmModuleInfo {
    /// Total code functions (non-imported).
    #[must_use]
    pub const fn code_function_count(&self) -> u32 {
        self.function_count.saturating_sub(self.import_count)
    }
}

// ── WasmLocalAnalysis ─────────────────────────────────────────────────────────

/// Analyzes local variable usage in a decompiled function.
#[derive(Debug, Clone, Default)]
pub struct WasmLocalAnalysis {
    /// Number of times each local is read.
    pub read_counts: Vec<u32>,
    /// Number of times each local is written.
    pub write_counts: Vec<u32>,
}

impl WasmLocalAnalysis {
    /// Analyze a function's statement list.
    #[must_use]
    pub fn analyze(stmts: &[WasmStmt], local_count: usize) -> Self {
        let mut reads = vec![0u32; local_count];
        let mut writes = vec![0u32; local_count];
        for stmt in stmts {
            Self::visit_stmt(stmt, &mut reads, &mut writes);
        }
        Self {
            read_counts: reads,
            write_counts: writes,
        }
    }

    fn visit_stmt(stmt: &WasmStmt, reads: &mut Vec<u32>, writes: &mut [u32]) {
        match stmt {
            WasmStmt::LocalSet { idx, value, .. } => {
                let idx = *idx as usize;
                if idx < writes.len() {
                    writes[idx] += 1;
                }
                Self::visit_expr(value, reads);
            }
            WasmStmt::ExprStmt(e) => Self::visit_expr(e, reads),
            WasmStmt::Return(Some(e)) => Self::visit_expr(e, reads),
            WasmStmt::Store { addr, value, .. } => {
                Self::visit_expr(addr, reads);
                Self::visit_expr(value, reads);
            }
            _ => {}
        }
    }

    fn visit_expr(expr: &WasmExpr, reads: &mut Vec<u32>) {
        match expr {
            WasmExpr::LocalGet { idx, .. } => {
                let idx = *idx as usize;
                if idx < reads.len() {
                    reads[idx] += 1;
                }
            }
            WasmExpr::BinOp { lhs, rhs, .. } => {
                Self::visit_expr(lhs, reads);
                Self::visit_expr(rhs, reads);
            }
            WasmExpr::UnaryOp { expr, .. } => Self::visit_expr(expr, reads),
            WasmExpr::Load { addr, .. } => Self::visit_expr(addr, reads),
            _ => {}
        }
    }

    /// Whether local `idx` is used at all.
    #[must_use]
    pub fn is_used(&self, idx: usize) -> bool {
        self.read_counts.get(idx).copied().unwrap_or(0) > 0
            || self.write_counts.get(idx).copied().unwrap_or(0) > 0
    }

    /// Locals that are written once and read once (likely single-assignment).
    #[must_use]
    pub fn single_assignment_locals(&self) -> Vec<usize> {
        (0..self.read_counts.len().min(self.write_counts.len()))
            .filter(|&i| self.write_counts[i] == 1 && self.read_counts[i] == 1)
            .collect()
    }
}

// ── WasmInlineState ───────────────────────────────────────────────────────────

/// Tracks inlining state during Wasm decompilation.
#[derive(Debug, Clone, Default)]
pub struct WasmInlineState {
    /// Nesting depth of block/loop/if constructs.
    pub block_depth: usize,
    /// Whether we are currently inside a loop.
    pub in_loop: bool,
    /// Branch target labels in scope.
    pub labels: Vec<u32>,
}

impl WasmInlineState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a label (entering a block/loop/if).
    pub fn push_label(&mut self, label: u32) {
        self.labels.push(label);
        self.block_depth += 1;
    }

    /// Pop a label (exiting a block/loop/if).
    pub fn pop_label(&mut self) -> Option<u32> {
        if self.block_depth > 0 {
            self.block_depth -= 1;
        }
        self.labels.pop()
    }

    /// Get the label at depth `d` (0 = innermost).
    #[must_use]
    pub fn label_at_depth(&self, d: usize) -> Option<u32> {
        let idx = self.labels.len().checked_sub(d + 1)?;
        self.labels.get(idx).copied()
    }
}

// ── WasmOptimizer ─────────────────────────────────────────────────────────────

/// Simple peephole optimizer over the decompiled statement list.
pub struct WasmOptimizer;

impl WasmOptimizer {
    /// Fold consecutive `i32.const` push / local.set pairs where the value is known.
    #[must_use]
    pub const fn fold_constants(stmts: Vec<WasmStmt>) -> Vec<WasmStmt> {
        // For now: identity; real implementation would substitute constants.
        stmts
    }

    /// Remove dead `unreachable!()` statements after a `return`.
    #[must_use]
    pub fn remove_dead_unreachable(stmts: Vec<WasmStmt>) -> Vec<WasmStmt> {
        let mut result = Vec::new();
        let mut seen_ret = false;
        for stmt in stmts {
            if seen_ret && matches!(stmt, WasmStmt::Unreachable) {
                continue;
            }
            if matches!(stmt, WasmStmt::Return(_)) {
                seen_ret = true;
            }
            result.push(stmt);
        }
        result
    }

    /// Count local.set statements for a given local index.
    #[must_use]
    pub fn count_local_sets(stmts: &[WasmStmt], target_idx: u32) -> usize {
        stmts
            .iter()
            .filter(|s| matches!(s, WasmStmt::LocalSet { idx, .. } if *idx == target_idx))
            .count()
    }
}

// ── FunctionDecompiler ────────────────────────────────────────────────────────

/// Decompiles a single Wasm function body into statements.
pub struct FunctionDecompiler {
    pub locals: LocalVarNaming,
    pub stmts: Vec<WasmStmt>,
}

/// Maximum number of local variables a decompiled function may declare.
///
/// A malicious or malformed module could supply a very large LEB128 local
/// count. Allocating `vec![…; count]` without a cap would exhaust process
/// memory before any per-element validation fires.
const MAX_LOCAL_COUNT: usize = 65_536;

impl FunctionDecompiler {
    /// Create a new decompiler with `n` i32 locals.
    ///
    /// `n` is silently capped at [`MAX_LOCAL_COUNT`] to prevent
    /// memory-exhaustion from attacker-controlled input.
    #[must_use]
    pub fn new(n: usize) -> Self {
        let n = n.min(MAX_LOCAL_COUNT);
        Self {
            locals: LocalVarNaming::new(n, WasmValueType::I32),
            stmts: Vec::new(),
        }
    }

    /// Decompile raw Wasm bytecode.
    pub fn decompile(&mut self, bytes: &[u8]) {
        let mut eb = ExpressionBuilder::new(self.locals.clone());
        let mut pos = 0;
        while pos < bytes.len() {
            match decode_wasm_one_mnemonic(bytes, pos) {
                Some((mnemonic, operands, size)) => {
                    if let Some(stmt) = eb.process(&mnemonic, &operands) {
                        self.stmts.push(stmt);
                    }
                    pos += size;
                }
                None => {
                    pos += 1;
                }
            }
        }
        // Drain the stack as expression statements
        while let Some(e) = eb.pop() {
            self.stmts.push(WasmStmt::ExprStmt(e));
        }
    }
}

// ── WasmDecompiler ────────────────────────────────────────────────────────────

/// Top-level Wasm decompiler.
pub struct WasmDecompiler {
    pub func_count: u32,
}

impl WasmDecompiler {
    #[must_use]
    pub const fn new() -> Self {
        Self { func_count: 0 }
    }

    /// Decompile a single function body with `local_count` locals.
    #[must_use]
    pub fn decompile_function(&mut self, bytes: &[u8], local_count: usize) -> DecompiledWasmFunc {
        self.func_count += 1;
        let idx = self.func_count - 1;
        let mut fd = FunctionDecompiler::new(local_count);
        fd.decompile(bytes);
        DecompiledWasmFunc {
            index: idx,
            stmts: fd.stmts,
            local_count,
        }
    }
}

impl Default for WasmDecompiler {
    fn default() -> Self {
        Self::new()
    }
}

/// A decompiled Wasm function.
#[derive(Debug, Clone)]
pub struct DecompiledWasmFunc {
    pub index: u32,
    pub stmts: Vec<WasmStmt>,
    pub local_count: usize,
}

impl DecompiledWasmFunc {
    /// Return `true` if the function has no statements (empty body).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.stmts.is_empty()
    }
}

// ── WasmPrinter ───────────────────────────────────────────────────────────────

/// Renders a decompiled Wasm function to a C-like string.
pub struct WasmPrinter {
    indent: usize,
}

impl WasmPrinter {
    #[must_use]
    pub const fn new() -> Self {
        Self { indent: 0 }
    }

    fn indent_str(&self) -> String {
        "  ".repeat(self.indent)
    }

    /// Render a function to a string.
    #[must_use]
    pub fn print_function(&mut self, func: &DecompiledWasmFunc) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "void func_{}({} locals) {{\n",
            func.index, func.local_count
        ));
        self.indent += 1;
        for stmt in &func.stmts {
            out.push_str(&format!("{}{}", self.indent_str(), stmt));
        }
        self.indent -= 1;
        out.push_str("}\n");
        out
    }

    /// Render a statement to string.
    #[must_use]
    pub fn print_stmt(&self, stmt: &WasmStmt) -> String {
        format!("{}{stmt}", self.indent_str())
    }
}

impl Default for WasmPrinter {
    fn default() -> Self {
        Self::new()
    }
}

// ── WasmMemoryModel ───────────────────────────────────────────────────────────

/// Represents the Wasm linear memory model.
#[derive(Debug, Clone)]
pub struct WasmMemoryModel {
    /// Memory size in pages (1 page = 64 KiB).
    pub pages: u32,
    /// Maximum pages, if limited.
    pub max_pages: Option<u32>,
    /// Whether the memory is shared (threads proposal).
    pub shared: bool,
}

impl WasmMemoryModel {
    /// Create a memory model with an initial size.
    #[must_use]
    pub const fn new(pages: u32) -> Self {
        Self {
            pages,
            max_pages: None,
            shared: false,
        }
    }

    /// Byte size of the current memory.
    #[must_use]
    pub const fn byte_size(&self) -> u64 {
        self.pages as u64 * 65536
    }

    /// Whether the given byte address is within bounds.
    #[must_use]
    pub fn in_bounds(&self, addr: u64, access_size: u64) -> bool {
        addr.checked_add(access_size)
            .map(|end| end <= self.byte_size())
            .unwrap_or(false)
    }
}

// ── WasmFunctionTable ─────────────────────────────────────────────────────────

/// Represents the Wasm function table (used by `call_indirect`).
#[derive(Debug, Clone, Default)]
pub struct WasmFunctionTable {
    /// Table entries (function indices or None for null references).
    pub entries: Vec<Option<u32>>,
}

impl WasmFunctionTable {
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            entries: vec![None; size],
        }
    }

    /// Set a table entry.
    pub fn set(&mut self, idx: usize, func_idx: u32) {
        if idx < self.entries.len() {
            self.entries[idx] = Some(func_idx);
        }
    }

    /// Get a table entry.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<u32> {
        self.entries.get(idx).copied().flatten()
    }

    /// Table size.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Helper used by FunctionDecompiler ────────────────────────────────────────

// This bridge function decodes one Wasm instruction and returns (mnemonic, operands, size).
// It must be visible within the crate.  We delegate to the top-level decoder logic.
pub(crate) fn decode_wasm_one_mnemonic(
    bytes: &[u8],
    offset: usize,
) -> Option<(String, String, usize)> {
    if offset >= bytes.len() {
        return None;
    }
    let remaining = &bytes[offset..];
    match decode_wasm_pub(remaining) {
        Ok((mn, ops, size, _)) => Some((mn, ops, size)),
        Err(_) => None,
    }
}

// We need a public re-export of the private decode_wasm function for the bridge.
// Since the function is private in lib.rs, expose it via a pub(crate) wrapper here.
pub(crate) fn decode_wasm_pub(
    bytes: &[u8],
) -> Result<(String, String, usize, rustre_core::arch::InstrFlags), CoreError> {
    // Delegate directly — decode_wasm is pub(crate) within the crate.
    super::decode_wasm_reexport(bytes)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- WasmExpr ---

    #[test]
    fn test_i32_const_display() {
        assert_eq!(WasmExpr::I32Const(42).to_string(), "42");
    }

    #[test]
    fn test_i64_const_display() {
        assert!(WasmExpr::I64Const(-1).to_string().contains("LL"));
    }

    #[test]
    fn test_null_local_get_display() {
        let e = WasmExpr::LocalGet {
            idx: 0,
            name: "v0".to_string(),
        };
        assert_eq!(e.to_string(), "v0");
    }

    #[test]
    fn test_binop_add_display() {
        let e = WasmExpr::BinOp {
            op: WasmBinOp::Add,
            lhs: Box::new(WasmExpr::I32Const(1)),
            rhs: Box::new(WasmExpr::I32Const(2)),
        };
        assert!(e.to_string().contains('+'));
    }

    #[test]
    fn test_call_display() {
        let e = WasmExpr::Call {
            func_idx: 3,
            args: Vec::new(),
        };
        assert!(e.to_string().contains("func_3"));
    }

    #[test]
    fn test_select_display() {
        let e = WasmExpr::Select {
            cond: Box::new(WasmExpr::I32Const(1)),
            a: Box::new(WasmExpr::I32Const(2)),
            b: Box::new(WasmExpr::I32Const(3)),
        };
        assert!(e.to_string().contains('?'));
    }

    #[test]
    fn test_unary_eqz_display() {
        let e = WasmExpr::UnaryOp {
            op: WasmUnaryOp::Eqz,
            expr: Box::new(WasmExpr::I32Const(0)),
        };
        assert!(e.to_string().contains('!'));
    }

    #[test]
    fn test_load_with_offset_display() {
        let e = WasmExpr::Load {
            mem_op: "i32.load".to_string(),
            addr: Box::new(WasmExpr::LocalGet {
                idx: 0,
                name: "v0".to_string(),
            }),
            offset: 4,
        };
        assert!(e.to_string().contains("+4"));
    }

    #[test]
    fn test_load_zero_offset_display() {
        let e = WasmExpr::Load {
            mem_op: "i32.load".to_string(),
            addr: Box::new(WasmExpr::I32Const(0)),
            offset: 0,
        };
        assert!(!e.to_string().contains("+0"));
    }

    #[test]
    fn test_memory_size_display() {
        assert_eq!(WasmExpr::MemorySize.to_string(), "memory.size()");
    }

    // --- WasmBinOp Display ---

    #[test]
    fn test_binop_display_eq() {
        assert_eq!(format!("{}", WasmBinOp::Eq), "==");
    }

    #[test]
    fn test_binop_display_shl() {
        assert_eq!(format!("{}", WasmBinOp::Shl), "<<");
    }

    #[test]
    fn test_binop_display_rotl() {
        assert_eq!(format!("{}", WasmBinOp::Rotl), "rotl");
    }

    // --- LocalVarNaming ---

    #[test]
    fn test_naming_default_names() {
        let n = LocalVarNaming::new(3, WasmValueType::I32);
        assert_eq!(n.name(0), "v0");
        assert_eq!(n.name(2), "v2");
    }

    #[test]
    fn test_naming_set_custom() {
        let mut n = LocalVarNaming::new(2, WasmValueType::I32);
        n.set_name(0, "counter".to_string());
        assert_eq!(n.name(0), "counter");
    }

    #[test]
    fn test_naming_out_of_range() {
        let n = LocalVarNaming::new(2, WasmValueType::I32);
        assert_eq!(n.name(99), "v99");
    }

    #[test]
    fn test_naming_declaration() {
        let n = LocalVarNaming::new(1, WasmValueType::I64);
        let decl = n.declaration(0);
        assert!(decl.contains("i64"));
        assert!(decl.contains("v0"));
    }

    #[test]
    fn test_naming_count() {
        let n = LocalVarNaming::new(5, WasmValueType::F32);
        assert_eq!(n.count(), 5);
    }

    // --- ControlFlowRecovery ---

    #[test]
    fn test_cf_depth_zero() {
        let cf = ControlFlowRecovery::new();
        assert_eq!(cf.depth(), 0);
    }

    #[test]
    fn test_cf_enter_exit() {
        let mut cf = ControlFlowRecovery::new();
        cf.enter_block();
        assert_eq!(cf.depth(), 1);
        cf.exit();
        assert_eq!(cf.depth(), 0);
    }

    #[test]
    fn test_cf_emit_break() {
        let mut cf = ControlFlowRecovery::new();
        cf.emit_break(0);
        assert_eq!(cf.stmts.len(), 1);
        assert!(matches!(cf.stmts[0], WasmStmt::Break(0)));
    }

    #[test]
    fn test_cf_emit_return() {
        let mut cf = ControlFlowRecovery::new();
        cf.emit_return(None);
        assert!(matches!(cf.stmts[0], WasmStmt::Return(None)));
    }

    #[test]
    fn test_cf_take_stmts() {
        let mut cf = ControlFlowRecovery::new();
        cf.emit(WasmStmt::Comment("hi".to_string()));
        let stmts = cf.take_stmts();
        assert_eq!(stmts.len(), 1);
        assert!(cf.stmts.is_empty());
    }

    // --- ExpressionBuilder ---

    #[test]
    fn test_eb_push_pop() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(5));
        assert_eq!(eb.depth(), 1);
        let e = eb.pop().unwrap();
        assert_eq!(e, WasmExpr::I32Const(5));
    }

    #[test]
    fn test_eb_process_i32_const() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.process("i32.const", "7");
        assert_eq!(eb.depth(), 1);
        assert_eq!(eb.pop().unwrap(), WasmExpr::I32Const(7));
    }

    #[test]
    fn test_eb_process_add() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(2));
        eb.push(WasmExpr::I32Const(3));
        eb.process("i32.add", "");
        assert_eq!(eb.depth(), 1);
        match eb.pop().unwrap() {
            WasmExpr::BinOp {
                op: WasmBinOp::Add, ..
            } => {}
            other => panic!("expected Add, got {other:?}"),
        }
    }

    #[test]
    fn test_eb_local_get_set() {
        let locals = LocalVarNaming::new(4, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.process("i32.const", "10");
        let stmt = eb.process("local.set", "2").unwrap();
        match stmt {
            WasmStmt::LocalSet { idx: 2, .. } => {}
            other => panic!("expected LocalSet, got {other:?}"),
        }
    }

    #[test]
    fn test_eb_return_value() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(0));
        let stmt = eb.process("return", "").unwrap();
        assert!(matches!(stmt, WasmStmt::Return(Some(_))));
    }

    #[test]
    fn test_eb_drop() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(1));
        eb.process("drop", "");
        assert_eq!(eb.depth(), 0);
    }

    // --- WasmDecompiler ---

    #[test]
    fn test_decompiler_default() {
        let d = WasmDecompiler::default();
        assert_eq!(d.func_count, 0);
    }

    #[test]
    fn test_decompile_empty_returns_no_stmts() {
        let mut d = WasmDecompiler::new();
        let f = d.decompile_function(&[], 0);
        assert_eq!(f.index, 0);
        assert!(f.is_empty());
    }

    #[test]
    fn test_decompile_increments_count() {
        let mut d = WasmDecompiler::new();
        let _ = d.decompile_function(&[], 0);
        let _ = d.decompile_function(&[], 0);
        assert_eq!(d.func_count, 2);
    }

    // --- WasmPrinter ---

    #[test]
    fn test_printer_empty_function() {
        let mut p = WasmPrinter::new();
        let f = DecompiledWasmFunc {
            index: 0,
            stmts: Vec::new(),
            local_count: 0,
        };
        let s = p.print_function(&f);
        assert!(s.contains("func_0"));
        assert!(s.contains('{'));
        assert!(s.contains('}'));
    }

    #[test]
    fn test_printer_stmt() {
        let p = WasmPrinter::new();
        let s = p.print_stmt(&WasmStmt::Comment("test".to_string()));
        assert!(s.contains("test"));
    }

    #[test]
    fn test_printer_with_stmts() {
        let mut p = WasmPrinter::new();
        let f = DecompiledWasmFunc {
            index: 1,
            stmts: vec![WasmStmt::Return(Some(WasmExpr::I32Const(0)))],
            local_count: 1,
        };
        let s = p.print_function(&f);
        assert!(s.contains("return"));
    }

    // --- WasmStmt display ---

    #[test]
    fn test_stmt_return_none() {
        let s = WasmStmt::Return(None).to_string();
        assert!(s.contains("return"));
    }

    #[test]
    fn test_stmt_break() {
        let s = WasmStmt::Break(2).to_string();
        assert!(s.contains("break"));
    }

    #[test]
    fn test_stmt_comment() {
        let s = WasmStmt::Comment("hi".to_string()).to_string();
        assert!(s.starts_with("//"));
    }

    // --- More ExpressionBuilder tests ---

    #[test]
    fn test_eb_i64_const() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.process("i64.const", "999");
        assert_eq!(eb.pop().unwrap(), WasmExpr::I64Const(999));
    }

    #[test]
    fn test_eb_global_get() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.process("global.get", "3");
        assert_eq!(eb.pop().unwrap(), WasmExpr::GlobalGet(3));
    }

    #[test]
    fn test_eb_global_set() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(0));
        let stmt = eb.process("global.set", "2").unwrap();
        assert!(matches!(stmt, WasmStmt::GlobalSet { idx: 2, .. }));
    }

    #[test]
    fn test_eb_i32_store() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(0)); // addr
        eb.push(WasmExpr::I32Const(42)); // value
        let stmt = eb.process("i32.store", "align=2 offset=0").unwrap();
        assert!(matches!(stmt, WasmStmt::Store { .. }));
    }

    #[test]
    fn test_eb_i32_load() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(4));
        eb.process("i32.load", "align=2 offset=0");
        assert_eq!(eb.depth(), 1);
    }

    #[test]
    fn test_eb_memory_size() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.process("memory.size", "");
        assert_eq!(eb.pop().unwrap(), WasmExpr::MemorySize);
    }

    #[test]
    fn test_eb_memory_grow() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(1));
        eb.process("memory.grow", "");
        assert!(matches!(eb.pop().unwrap(), WasmExpr::MemoryGrow(_)));
    }

    #[test]
    fn test_eb_select() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(1));
        eb.push(WasmExpr::I32Const(2));
        eb.push(WasmExpr::I32Const(1));
        eb.process("select", "");
        assert!(matches!(eb.pop().unwrap(), WasmExpr::Select { .. }));
    }

    #[test]
    fn test_eb_i32_sub() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(10));
        eb.push(WasmExpr::I32Const(3));
        eb.process("i32.sub", "");
        assert!(matches!(
            eb.pop().unwrap(),
            WasmExpr::BinOp {
                op: WasmBinOp::Sub,
                ..
            }
        ));
    }

    #[test]
    fn test_eb_i32_and() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(0xFF));
        eb.push(WasmExpr::I32Const(0x0F));
        eb.process("i32.and", "");
        assert!(matches!(
            eb.pop().unwrap(),
            WasmExpr::BinOp {
                op: WasmBinOp::And,
                ..
            }
        ));
    }

    #[test]
    fn test_eb_i32_eq() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.push(WasmExpr::I32Const(1));
        eb.push(WasmExpr::I32Const(1));
        eb.process("i32.eq", "");
        assert!(matches!(
            eb.pop().unwrap(),
            WasmExpr::BinOp {
                op: WasmBinOp::Eq,
                ..
            }
        ));
    }

    #[test]
    fn test_eb_call() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        eb.process("call", "7");
        assert!(matches!(
            eb.pop().unwrap(),
            WasmExpr::Call { func_idx: 7, .. }
        ));
    }

    // --- Additional ExpressionBuilder not-found cases ---

    #[test]
    fn test_eb_nop_no_stack_change() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        let stmt = eb.process("nop", "");
        assert!(stmt.is_none());
        assert_eq!(eb.depth(), 0);
    }

    #[test]
    fn test_eb_unknown_mnemonic() {
        let locals = LocalVarNaming::new(0, WasmValueType::I32);
        let mut eb = ExpressionBuilder::new(locals);
        let stmt = eb.process("completely_unknown", "");
        assert!(stmt.is_none());
    }

    // --- parse_offset helper ---

    #[test]
    fn test_parse_offset_zero() {
        assert_eq!(super::parse_offset("align=2 offset=0"), 0);
    }

    #[test]
    fn test_parse_offset_nonzero() {
        assert_eq!(super::parse_offset("align=2 offset=8"), 8);
    }

    #[test]
    fn test_parse_offset_missing() {
        assert_eq!(super::parse_offset("align=2"), 0);
    }
}
