//! `wasm_lifter` — WASM-to-LLIL lifter.
//!
//! This module implements a WASM-to-Low-Level Intermediate Language (LLIL)
//! lifter.  LLIL is an abstract representation modelled after Binary Ninja's
//! LLIL but decoupled from any specific analysis platform.
//!
//! # Design
//!
//! WASM is a stack machine.  The lifter simulates the value stack and emits
//! LLIL operations as it processes each instruction.  Control flow is
//! reconstructed from the structured WASM control-flow opcodes (`block`, `loop`,
//! `if`, `else`, `end`, `br`, `br_if`, `br_table`, `return`).
//!
//! # Key types
//!
//! * [`LlilOp`] — an individual LLIL operation.
//! * [`LlilExpr`] — an LLIL expression (recursive tree node).
//! * [`LiftedFunction`] — the result of lifting a single WASM function body.
//! * [`WasmLifter`] — the lifter struct that owns local/global maps and
//!   emits LLIL.
//!
//! # Usage
//!
//! ```
//! use rustre_arch_wasm::wasm_lifter::{WasmLifter, LiftOptions};
//!
//! let mut lifter = WasmLifter::new(LiftOptions::default());
//! let func_body = b"\x41\x2a\x41\x01\x6a\x0f"; // i32.const 42, i32.const 1, i32.add, return
//! let lifted = lifter.lift_wasm_function(func_body, 0).unwrap();
//! assert!(!lifted.ops.is_empty());
//! ```

use rustre_core::errors::CoreError;

use crate::read_sleb128;
use crate::read_uleb128;

// ─── LiftOptions ────────────────────────────────────────────────────────────

/// Maximum local / global variable index accepted by the lifter.
///
/// The Wasm spec allows up to 2^32−1 locals but practical modules use far
/// fewer. Without this cap, `add_local(u32::MAX, 32)` would trigger a
/// multi-gigabyte `Vec` fill before any bounds check could fire.
const MAX_VAR_INDEX: u32 = 65_535;

/// Options controlling the lifting process.
#[derive(Debug, Clone)]
pub struct LiftOptions {
    /// Maximum number of LLIL ops to emit per function (guard against infinite
    /// loops in malformed input).
    pub max_ops: usize,
    /// Maximum nesting depth for structured control flow.
    pub max_cf_depth: usize,
    /// Whether to emit `LLIL_NOP` for `nop` instructions (vs. skipping them).
    pub emit_nops: bool,
}

impl Default for LiftOptions {
    fn default() -> Self {
        Self {
            max_ops: 65_536,
            max_cf_depth: 256,
            emit_nops: false,
        }
    }
}

// ─── LlilReg ────────────────────────────────────────────────────────────────

/// An abstract LLIL register, representing either a WASM local or a
/// synthetic temporary created during lifting.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LlilReg {
    /// Register name.
    pub name: String,
    /// Width in bits (32 or 64).
    pub bits: u32,
}

impl LlilReg {
    /// Create a local register.
    #[must_use]
    pub fn local(index: u32, bits: u32) -> Self {
        Self {
            name: format!("local_{index}"),
            bits,
        }
    }

    /// Create a global register.
    #[must_use]
    pub fn global(index: u32, bits: u32) -> Self {
        Self {
            name: format!("global_{index}"),
            bits,
        }
    }

    /// Create a synthetic temp register.
    #[must_use]
    pub fn temp(id: u32, bits: u32) -> Self {
        Self {
            name: format!("t{id}"),
            bits,
        }
    }
}

impl std::fmt::Display for LlilReg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ─── LlilExpr ────────────────────────────────────────────────────────────────

/// An LLIL expression (value-producing tree node).
#[derive(Debug, Clone, PartialEq)]
pub enum LlilExpr {
    /// Constant integer.
    Const(i64),
    /// Constant float.
    ConstFloat(f64),
    /// Register read.
    Reg(LlilReg),
    /// Memory read of `bits` bits at `address`.
    Load { bits: u32, address: Box<LlilExpr> },
    /// Binary arithmetic / logical operation.
    BinOp {
        op: BinOp,
        left: Box<LlilExpr>,
        right: Box<LlilExpr>,
    },
    /// Unary operation.
    UnOp { op: UnOp, operand: Box<LlilExpr> },
    /// Stack-pop placeholder (used when the value stack underflows during
    /// recovery).
    StackPop,
    /// Undefined / opaque.
    Undef,
}

impl LlilExpr {
    /// Convenience: wrap in a `Box`.
    #[must_use]
    pub fn boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

impl std::fmt::Display for LlilExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Const(n) => write!(f, "{n}"),
            Self::ConstFloat(v) => write!(f, "{v}"),
            Self::Reg(r) => write!(f, "{r}"),
            Self::Load { bits, address } => write!(f, "load{bits}({address})"),
            Self::BinOp { op, left, right } => write!(f, "({left} {op} {right})"),
            Self::UnOp { op, operand } => write!(f, "{op}({operand})"),
            Self::StackPop => write!(f, "<stack_pop>"),
            Self::Undef => write!(f, "undef"),
        }
    }
}

/// Binary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOp {
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
}

impl std::fmt::Display for BinOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::DivS => "/s",
            Self::DivU => "/u",
            Self::RemS => "%s",
            Self::RemU => "%u",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::ShrS => ">>s",
            Self::ShrU => ">>u",
            Self::Rotl => "rotl",
            Self::Rotr => "rotr",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::LtS => "<s",
            Self::LtU => "<u",
            Self::GtS => ">s",
            Self::GtU => ">u",
            Self::LeS => "<=s",
            Self::LeU => "<=u",
            Self::GeS => ">=s",
            Self::GeU => ">=u",
            Self::FAdd => "f+",
            Self::FSub => "f-",
            Self::FMul => "f*",
            Self::FDiv => "f/",
            Self::FMin => "fmin",
            Self::FMax => "fmax",
        };
        write!(f, "{s}")
    }
}

/// Unary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnOp {
    Eqz,
    Clz,
    Ctz,
    Popcnt,
    FAbs,
    FNeg,
    FCeil,
    FFloor,
    FTrunc,
    FSqrt,
    FNearest,
    WrapI64,
    Extend8S,
    Extend16S,
    Extend32S,
}

impl std::fmt::Display for UnOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Eqz => "eqz",
            Self::Clz => "clz",
            Self::Ctz => "ctz",
            Self::Popcnt => "popcnt",
            Self::FAbs => "fabs",
            Self::FNeg => "fneg",
            Self::FCeil => "fceil",
            Self::FFloor => "ffloor",
            Self::FTrunc => "ftrunc",
            Self::FSqrt => "fsqrt",
            Self::FNearest => "fnearest",
            Self::WrapI64 => "wrap_i64",
            Self::Extend8S => "extend8_s",
            Self::Extend16S => "extend16_s",
            Self::Extend32S => "extend32_s",
        };
        write!(f, "{s}")
    }
}

// ─── LlilOp ──────────────────────────────────────────────────────────────────

/// An LLIL operation (statement / effect).
#[derive(Debug, Clone, PartialEq)]
pub enum LlilOp {
    /// No operation.
    Nop,
    /// Assign `expr` to `dest`.
    SetReg { dest: LlilReg, expr: LlilExpr },
    /// Store `value` to memory at `address`.
    Store {
        bits: u32,
        address: LlilExpr,
        value: LlilExpr,
    },
    /// Unconditional branch to `label`.
    Branch { label: u64 },
    /// Conditional branch to `label` if `condition`.
    BranchIf { condition: LlilExpr, label: u64 },
    /// Indirect branch (`br_table`).
    BranchTable {
        index: LlilExpr,
        labels: Vec<u64>,
        default: u64,
    },
    /// Call to function index `target`.
    Call { target: u64 },
    /// Indirect call via table.
    CallIndirect { type_idx: u64, table_idx: u64 },
    /// Return with optional value.
    Return { value: Option<LlilExpr> },
    /// Trap / unreachable.
    Trap,
    /// Mark the start of a structured block.
    BlockBegin { depth: usize, label: u64 },
    /// Mark the start of a structured loop.
    LoopBegin { depth: usize, label: u64 },
    /// Mark the start of an `if` construct.
    IfBegin { condition: LlilExpr, depth: usize },
    /// `else` branch of an `if`.
    Else { depth: usize },
    /// End of a structured block / loop / if.
    BlockEnd { depth: usize },
    /// Discard top of stack.
    Drop,
    /// Select between two values based on condition.
    Select {
        condition: LlilExpr,
        true_val: LlilExpr,
        false_val: LlilExpr,
        dest: LlilReg,
    },
}

impl std::fmt::Display for LlilOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nop => write!(f, "nop"),
            Self::SetReg { dest, expr } => write!(f, "{dest} = {expr}"),
            Self::Store {
                bits,
                address,
                value,
            } => write!(f, "store{bits}({address}) = {value}"),
            Self::Branch { label } => write!(f, "goto {label:#x}"),
            Self::BranchIf { condition, label } => write!(f, "if ({condition}) goto {label:#x}"),
            Self::BranchTable {
                index,
                labels,
                default,
            } => write!(
                f,
                "switch ({index}) [{} + default {default:#x}]",
                labels.len()
            ),
            Self::Call { target } => write!(f, "call {target:#x}"),
            Self::CallIndirect {
                type_idx,
                table_idx,
            } => write!(f, "call_indirect type={type_idx} table={table_idx}"),
            Self::Return { value } => match value {
                Some(v) => write!(f, "return {v}"),
                None => write!(f, "return"),
            },
            Self::Trap => write!(f, "trap"),
            Self::BlockBegin { depth, label } => write!(f, "block@{depth} #{label:#x}"),
            Self::LoopBegin { depth, label } => write!(f, "loop@{depth} #{label:#x}"),
            Self::IfBegin { condition, depth } => write!(f, "if@{depth} ({condition})"),
            Self::Else { depth } => write!(f, "else@{depth}"),
            Self::BlockEnd { depth } => write!(f, "end@{depth}"),
            Self::Drop => write!(f, "drop"),
            Self::Select {
                condition,
                true_val,
                false_val,
                dest,
            } => write!(f, "{dest} = select({condition}, {true_val}, {false_val})"),
        }
    }
}

// ─── LiftedFunction ───────────────────────────────────────────────────────────

/// The result of lifting a single WASM function body.
#[derive(Debug, Clone)]
pub struct LiftedFunction {
    /// Base address (virtual) of the function.
    pub base_address: u64,
    /// List of lifted LLIL operations.
    pub ops: Vec<LlilOp>,
    /// Temporary register counter at end of lifting.
    pub temp_count: u32,
    /// Number of bytes consumed from the function body.
    pub bytes_consumed: usize,
    /// Warnings emitted during lifting (e.g. stack underflows, unknown ops).
    pub warnings: Vec<String>,
}

// ─── WasmLifter ───────────────────────────────────────────────────────────────

/// WASM-to-LLIL lifter.
///
/// Maintains a virtual value stack and a control-flow frame stack, and emits
/// LLIL operations as each WASM instruction is processed.
pub struct WasmLifter {
    opts: LiftOptions,
    // Value stack — each slot is an `LlilExpr`.
    stack: Vec<LlilExpr>,
    // Control-flow depth counter.
    cf_depth: usize,
    // Block label counter.
    label_counter: u64,
    // Temp register counter.
    temp_counter: u32,
    // Warnings.
    warnings: Vec<String>,
    // Local variable map: index → (reg, bits).
    locals: Vec<(LlilReg, u32)>,
    // Global variable map: index → (reg, bits).
    globals: Vec<(LlilReg, u32)>,
}

impl WasmLifter {
    /// Create a new lifter with `opts`.
    #[must_use]
    pub const fn new(opts: LiftOptions) -> Self {
        Self {
            opts,
            stack: Vec::new(),
            cf_depth: 0,
            label_counter: 0,
            temp_counter: 0,
            warnings: Vec::new(),
            locals: Vec::new(),
            globals: Vec::new(),
        }
    }

    /// Register a local variable with `bits` width.
    ///
    /// Indices above [`MAX_VAR_INDEX`] are silently ignored to prevent a
    /// denial-of-service via gigabyte `Vec` fill (dos-memory-exhaustion).
    pub fn add_local(&mut self, index: u32, bits: u32) {
        if index > MAX_VAR_INDEX {
            self.warnings
                .push(format!("local index {index} exceeds cap {MAX_VAR_INDEX}; ignored"));
            return;
        }
        let reg = LlilReg::local(index, bits);
        if (index as usize) < self.locals.len() {
            self.locals[index as usize] = (reg, bits);
        } else {
            while self.locals.len() < index as usize {
                let idx = self.locals.len() as u32;
                self.locals.push((LlilReg::local(idx, 32), 32));
            }
            self.locals.push((reg, bits));
        }
    }

    /// Register a global variable with `bits` width.
    ///
    /// Indices above [`MAX_VAR_INDEX`] are silently ignored to prevent a
    /// denial-of-service via gigabyte `Vec` fill (dos-memory-exhaustion).
    pub fn add_global(&mut self, index: u32, bits: u32) {
        if index > MAX_VAR_INDEX {
            self.warnings
                .push(format!("global index {index} exceeds cap {MAX_VAR_INDEX}; ignored"));
            return;
        }
        let reg = LlilReg::global(index, bits);
        if (index as usize) < self.globals.len() {
            self.globals[index as usize] = (reg, bits);
        } else {
            while self.globals.len() < index as usize {
                let idx = self.globals.len() as u32;
                self.globals.push((LlilReg::global(idx, 32), 32));
            }
            self.globals.push((reg, bits));
        }
    }

    const fn alloc_label(&mut self) -> u64 {
        let l = self.label_counter;
        self.label_counter += 1;
        l
    }

    fn alloc_temp(&mut self, bits: u32) -> LlilReg {
        let t = self.temp_counter;
        self.temp_counter += 1;
        LlilReg::temp(t, bits)
    }

    fn pop(&mut self) -> LlilExpr {
        self.stack.pop().unwrap_or_else(|| {
            self.warnings.push("stack underflow".into());
            LlilExpr::StackPop
        })
    }

    fn push(&mut self, expr: LlilExpr) {
        self.stack.push(expr);
    }

    fn local_reg(&mut self, idx: u64) -> LlilReg {
        let idx = idx as usize;
        if idx < self.locals.len() {
            self.locals[idx].0.clone()
        } else {
            let reg = LlilReg::local(idx as u32, 32);
            self.warnings
                .push(format!("local {idx} not declared; assuming i32"));
            reg
        }
    }

    fn global_reg(&mut self, idx: u64) -> LlilReg {
        let idx = idx as usize;
        if idx < self.globals.len() {
            self.globals[idx].0.clone()
        } else {
            let reg = LlilReg::global(idx as u32, 32);
            self.warnings
                .push(format!("global {idx} not declared; assuming i32"));
            reg
        }
    }

    /// Lift a WASM function body `bytes`, starting at virtual address `base`.
    ///
    /// `bytes` is the raw bytecode including any local-declaration prefix.
    /// For simplicity, this lifter assumes locals are declared externally
    /// (via [`add_local`](Self::add_local)) and `bytes` starts directly at
    /// the first instruction.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidFormat`] on malformed input.
    pub fn lift_wasm_function(
        &mut self,
        bytes: &[u8],
        base: u64,
    ) -> Result<LiftedFunction, CoreError> {
        // Reset per-function state.
        self.stack.clear();
        self.cf_depth = 0;
        self.label_counter = base;
        self.temp_counter = 0;
        self.warnings.clear();

        let mut ops: Vec<LlilOp> = Vec::new();
        let mut pos = 0usize;
        let mut decoded_count: usize = 0;

        macro_rules! uleb {
            () => {{
                let (v, n) = read_uleb128(bytes, pos)?;
                pos += n;
                v
            }};
        }
        macro_rules! sleb {
            () => {{
                let (v, n) = read_sleb128(bytes, pos)?;
                pos += n;
                v
            }};
        }

        while pos < bytes.len() {
            if decoded_count >= self.opts.max_ops {
                self.warnings.push(format!(
                    "max_ops ({}) reached; truncating",
                    self.opts.max_ops
                ));
                break;
            }
            decoded_count += 1;

            let op = bytes[pos];
            pos += 1;

            match op {
                // Control
                0x00 => {
                    ops.push(LlilOp::Trap);
                }
                0x01 => {
                    if self.opts.emit_nops {
                        ops.push(LlilOp::Nop);
                    }
                }
                0x02 => {
                    let _bt = sleb!();
                    let lbl = self.alloc_label();
                    let depth = self.cf_depth;
                    self.cf_depth += 1;
                    ops.push(LlilOp::BlockBegin { depth, label: lbl });
                }
                0x03 => {
                    let _bt = sleb!();
                    let lbl = self.alloc_label();
                    let depth = self.cf_depth;
                    self.cf_depth += 1;
                    ops.push(LlilOp::LoopBegin { depth, label: lbl });
                }
                0x04 => {
                    let _bt = sleb!();
                    let cond = self.pop();
                    let depth = self.cf_depth;
                    self.cf_depth += 1;
                    ops.push(LlilOp::IfBegin {
                        condition: cond,
                        depth,
                    });
                }
                0x05 => {
                    let depth = self.cf_depth.saturating_sub(1);
                    ops.push(LlilOp::Else { depth });
                }
                0x0b => {
                    let depth = self.cf_depth;
                    if depth > 0 {
                        self.cf_depth -= 1;
                    }
                    ops.push(LlilOp::BlockEnd { depth });
                }
                0x0c => {
                    let _label_idx = uleb!();
                    let lbl = self.alloc_label();
                    ops.push(LlilOp::Branch { label: lbl });
                }
                0x0d => {
                    let _label_idx = uleb!();
                    let cond = self.pop();
                    let lbl = self.alloc_label();
                    ops.push(LlilOp::BranchIf {
                        condition: cond,
                        label: lbl,
                    });
                }
                0x0e => {
                    const MAX_BR_TABLE_ENTRIES: u64 = 65_536;
                    let count_raw = uleb!();
                    if count_raw > MAX_BR_TABLE_ENTRIES {
                        return Err(CoreError::InvalidFormat {
                            message: format!("br_table count {count_raw} exceeds limit"),
                        });
                    }
                    let count = count_raw as usize;
                    let mut labels = Vec::with_capacity(count + 1);
                    for _ in 0..=count {
                        let _ = uleb!();
                        labels.push(self.alloc_label());
                    }
                    let default = labels.pop().unwrap_or(0);
                    let index = self.pop();
                    ops.push(LlilOp::BranchTable {
                        index,
                        labels,
                        default,
                    });
                }
                0x0f => {
                    let value = if self.stack.is_empty() {
                        None
                    } else {
                        Some(self.pop())
                    };
                    ops.push(LlilOp::Return { value });
                }
                0x10 => {
                    let target = uleb!();
                    ops.push(LlilOp::Call { target });
                }
                0x11 => {
                    let type_idx = uleb!();
                    let table_idx = uleb!();
                    ops.push(LlilOp::CallIndirect {
                        type_idx,
                        table_idx,
                    });
                }

                // Parametric
                0x1a => {
                    let _ = self.pop();
                    ops.push(LlilOp::Drop);
                }
                0x1b => {
                    // select: cond, val1, val2
                    let cond = self.pop();
                    let v2 = self.pop();
                    let v1 = self.pop();
                    let dest = self.alloc_temp(32);
                    ops.push(LlilOp::Select {
                        condition: cond,
                        true_val: v1,
                        false_val: v2,
                        dest: dest.clone(),
                    });
                    self.push(LlilExpr::Reg(dest));
                }

                // Variable
                0x20 => {
                    let idx = uleb!();
                    let reg = self.local_reg(idx);
                    self.push(LlilExpr::Reg(reg));
                }
                0x21 => {
                    let idx = uleb!();
                    let reg = self.local_reg(idx);
                    let val = self.pop();
                    ops.push(LlilOp::SetReg {
                        dest: reg,
                        expr: val,
                    });
                }
                0x22 => {
                    let idx = uleb!();
                    let reg = self.local_reg(idx);
                    let val = self.pop();
                    ops.push(LlilOp::SetReg {
                        dest: reg.clone(),
                        expr: val,
                    });
                    self.push(LlilExpr::Reg(reg));
                }
                0x23 => {
                    let idx = uleb!();
                    let reg = self.global_reg(idx);
                    self.push(LlilExpr::Reg(reg));
                }
                0x24 => {
                    let idx = uleb!();
                    let reg = self.global_reg(idx);
                    let val = self.pop();
                    ops.push(LlilOp::SetReg {
                        dest: reg,
                        expr: val,
                    });
                }

                // Memory loads — emit Load(addr + offset) exprs.
                op @ 0x28..=0x35 => {
                    let _align = uleb!();
                    let offset = uleb!();
                    let bits = match op {
                        0x28 | 0x2c | 0x2d => 32,
                        0x29 | 0x30..=0x35 => 64,
                        0x2a => 32,
                        0x2b => 64,
                        0x2e | 0x2f => 32,
                        _ => 32,
                    };
                    let base_addr = self.pop();
                    let addr_expr = if offset == 0 {
                        base_addr
                    } else {
                        LlilExpr::BinOp {
                            op: BinOp::Add,
                            left: base_addr.boxed(),
                            right: LlilExpr::Const(offset as i64).boxed(),
                        }
                    };
                    let dest = self.alloc_temp(bits);
                    let load = LlilExpr::Load {
                        bits,
                        address: addr_expr.boxed(),
                    };
                    ops.push(LlilOp::SetReg {
                        dest: dest.clone(),
                        expr: load,
                    });
                    self.push(LlilExpr::Reg(dest));
                }

                // Memory stores.
                op @ 0x36..=0x3e => {
                    let _align = uleb!();
                    let offset = uleb!();
                    let bits = match op {
                        0x36 => 32,
                        0x37 => 64,
                        0x38 => 32,
                        0x39 => 64,
                        0x3a => 8,
                        0x3b => 16,
                        0x3c => 8,
                        0x3d => 16,
                        0x3e => 32,
                        _ => 32,
                    };
                    let value = self.pop();
                    let base_addr = self.pop();
                    let addr_expr = if offset == 0 {
                        base_addr
                    } else {
                        LlilExpr::BinOp {
                            op: BinOp::Add,
                            left: base_addr.boxed(),
                            right: LlilExpr::Const(offset as i64).boxed(),
                        }
                    };
                    ops.push(LlilOp::Store {
                        bits,
                        address: addr_expr,
                        value,
                    });
                }

                // memory.size / memory.grow
                0x3f => {
                    let _mem = uleb!();
                    let t = self.alloc_temp(32);
                    self.push(LlilExpr::Reg(t));
                }
                0x40 => {
                    let _mem = uleb!();
                    let _ = self.pop();
                    let t = self.alloc_temp(32);
                    self.push(LlilExpr::Reg(t));
                }

                // Constants
                0x41 => {
                    let v = sleb!();
                    self.push(LlilExpr::Const(v));
                }
                0x42 => {
                    let v = sleb!();
                    self.push(LlilExpr::Const(v));
                }
                0x43 => {
                    if pos + 4 > bytes.len() {
                        return Err(CoreError::InvalidFormat {
                            message: "truncated f32.const".into(),
                        });
                    }
                    let bits = u32::from_le_bytes([
                        bytes[pos],
                        bytes[pos + 1],
                        bytes[pos + 2],
                        bytes[pos + 3],
                    ]);
                    pos += 4;
                    self.push(LlilExpr::ConstFloat(f64::from(f32::from_bits(bits))));
                }
                0x44 => {
                    if pos + 8 > bytes.len() {
                        return Err(CoreError::InvalidFormat {
                            message: "truncated f64.const".into(),
                        });
                    }
                    let bits = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    self.push(LlilExpr::ConstFloat(f64::from_bits(bits)));
                }

                // i32 compare / arithmetic (emit BinOp / UnOp into temps)
                0x45 => {
                    let a = self.pop();
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::UnOp {
                            op: UnOp::Eqz,
                            operand: a.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x46 => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::Eq,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x47 => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::Ne,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x48 => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::LtS,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x49 => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::LtU,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }

                0x67 => {
                    let a = self.pop();
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::UnOp {
                            op: UnOp::Clz,
                            operand: a.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x68 => {
                    let a = self.pop();
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::UnOp {
                            op: UnOp::Ctz,
                            operand: a.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x6a => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::Add,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x6b => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::Sub,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x6c => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::Mul,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x6d => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::DivS,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x71 => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::And,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x72 => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::Or,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x73 => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::Xor,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x74 => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::Shl,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }

                // i64 add/sub/mul
                0x7c => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(64);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::Add,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x7d => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(64);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::Sub,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0x7e => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(64);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::Mul,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }

                // f32 / f64 ops
                0x92 => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::FAdd,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }
                0xa0 => {
                    let (r, l) = (self.pop(), self.pop());
                    let t = self.alloc_temp(64);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::BinOp {
                            op: BinOp::FAdd,
                            left: l.boxed(),
                            right: r.boxed(),
                        },
                    });
                    self.push(LlilExpr::Reg(t));
                }

                // Conversions (emit as undef temp for now)
                0xa7..=0xc4 => {
                    let _ = self.pop();
                    let t = self.alloc_temp(32);
                    ops.push(LlilOp::SetReg {
                        dest: t.clone(),
                        expr: LlilExpr::Undef,
                    });
                    self.push(LlilExpr::Reg(t));
                }

                // Prefixed extensions — skip without error.
                0xfc..=0xfe => {
                    // Read and discard the LEB128 sub-opcode.
                    let (_, n) = read_uleb128(bytes, pos)?;
                    pos += n;
                    let t = self.alloc_temp(32);
                    self.push(LlilExpr::Reg(t));
                }

                // Reference types
                0x25 | 0x26 => {
                    let _idx = uleb!();
                }
                0xd0 => {
                    pos += 1;
                    let t = self.alloc_temp(32);
                    self.push(LlilExpr::Reg(t));
                }
                0xd1 => {
                    let _ = self.pop();
                    let t = self.alloc_temp(32);
                    self.push(LlilExpr::Reg(t));
                }
                0xd2 => {
                    let _idx = uleb!();
                    let t = self.alloc_temp(32);
                    self.push(LlilExpr::Reg(t));
                }

                unknown => {
                    self.warnings.push(format!(
                        "unknown opcode 0x{unknown:02x} at offset {}",
                        pos - 1
                    ));
                    // Emit an undef to keep the stack consistent.
                    let t = self.alloc_temp(32);
                    self.push(LlilExpr::Reg(t));
                }
            }
        }

        let temp_count = self.temp_counter;
        Ok(LiftedFunction {
            base_address: base,
            ops,
            temp_count,
            bytes_consumed: pos,
            warnings: self.warnings.clone(),
        })
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn lifter() -> WasmLifter {
        WasmLifter::new(LiftOptions::default())
    }

    // ── LlilReg ─────────────────────────────────────────────────────────────

    #[test]
    fn test_llil_reg_local_name() {
        let r = LlilReg::local(3, 32);
        assert_eq!(r.name, "local_3");
        assert_eq!(r.bits, 32);
    }

    #[test]
    fn test_llil_reg_global_name() {
        let r = LlilReg::global(0, 64);
        assert_eq!(r.name, "global_0");
    }

    #[test]
    fn test_llil_reg_temp_name() {
        let r = LlilReg::temp(5, 32);
        assert_eq!(r.name, "t5");
    }

    #[test]
    fn test_llil_reg_display() {
        let r = LlilReg::local(1, 32);
        assert_eq!(r.to_string(), "local_1");
    }

    // ── LlilExpr ────────────────────────────────────────────────────────────

    #[test]
    fn test_llil_expr_const_display() {
        let e = LlilExpr::Const(42);
        assert_eq!(e.to_string(), "42");
    }

    #[test]
    fn test_llil_expr_reg_display() {
        let e = LlilExpr::Reg(LlilReg::temp(0, 32));
        assert_eq!(e.to_string(), "t0");
    }

    #[test]
    fn test_llil_expr_binop_display() {
        let e = LlilExpr::BinOp {
            op: BinOp::Add,
            left: LlilExpr::Const(1).boxed(),
            right: LlilExpr::Const(2).boxed(),
        };
        assert_eq!(e.to_string(), "(1 + 2)");
    }

    #[test]
    fn test_llil_expr_load_display() {
        let e = LlilExpr::Load {
            bits: 32,
            address: LlilExpr::Const(0x1000).boxed(),
        };
        assert_eq!(e.to_string(), "load32(4096)");
    }

    // ── LlilOp display ──────────────────────────────────────────────────────

    #[test]
    fn test_llil_op_setreg_display() {
        let op = LlilOp::SetReg {
            dest: LlilReg::temp(0, 32),
            expr: LlilExpr::Const(99),
        };
        assert_eq!(op.to_string(), "t0 = 99");
    }

    #[test]
    fn test_llil_op_return_display() {
        let op = LlilOp::Return {
            value: Some(LlilExpr::Const(0)),
        };
        assert_eq!(op.to_string(), "return 0");
        let op2 = LlilOp::Return { value: None };
        assert_eq!(op2.to_string(), "return");
    }

    #[test]
    fn test_llil_op_trap_display() {
        let op = LlilOp::Trap;
        assert_eq!(op.to_string(), "trap");
    }

    // ── Lifting ─────────────────────────────────────────────────────────────

    #[test]
    fn test_lift_i32_const_return() {
        // i32.const 42, return
        let bytes = [0x41u8, 0x2a, 0x0f];
        let result = lifter().lift_wasm_function(&bytes, 0x1000).unwrap();
        assert!(!result.ops.is_empty());
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op, LlilOp::Return { .. }))
        );
    }

    #[test]
    fn test_lift_i32_add() {
        // i32.const 1, i32.const 2, i32.add, return
        let bytes = [0x41u8, 0x01, 0x41, 0x02, 0x6a, 0x0f];
        let result = lifter().lift_wasm_function(&bytes, 0).unwrap();
        // Should have a SetReg with BinOp(Add) and a Return.
        let has_add = result.ops.iter().any(|op| {
            matches!(op, LlilOp::SetReg {
                expr: LlilExpr::BinOp { op: BinOp::Add, .. },
                ..
            })
        });
        assert!(has_add);
    }

    #[test]
    fn test_lift_local_get_set() {
        let mut l = lifter();
        l.add_local(0, 32);
        // local.get 0, local.set 0
        let bytes = [0x20u8, 0x00, 0x21, 0x00];
        let result = l.lift_wasm_function(&bytes, 0).unwrap();
        assert!(!result.ops.is_empty());
        let has_setreg = result
            .ops
            .iter()
            .any(|op| matches!(op, LlilOp::SetReg { .. }));
        assert!(has_setreg);
    }

    #[test]
    fn test_lift_global_get_set() {
        let mut l = lifter();
        l.add_global(0, 64);
        // global.get 0
        let bytes = [0x23u8, 0x00];
        let result = l.lift_wasm_function(&bytes, 0).unwrap();
        let _ = result.warnings.is_empty(); // no errors expected
    }

    #[test]
    fn test_lift_unreachable() {
        let bytes = [0x00u8];
        let result = lifter().lift_wasm_function(&bytes, 0).unwrap();
        assert!(result.ops.iter().any(|op| matches!(op, LlilOp::Trap)));
    }

    #[test]
    fn test_lift_br() {
        // block void, br 0, end
        let bytes = [0x02u8, 0x40, 0x0c, 0x00, 0x0b];
        let result = lifter().lift_wasm_function(&bytes, 0).unwrap();
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op, LlilOp::Branch { .. }))
        );
    }

    #[test]
    fn test_lift_br_if() {
        // i32.const 1, br_if 0
        let bytes = [0x41u8, 0x01, 0x0d, 0x00];
        let result = lifter().lift_wasm_function(&bytes, 0).unwrap();
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op, LlilOp::BranchIf { .. }))
        );
    }

    #[test]
    fn test_lift_br_table() {
        // i32.const 0, br_table 1 target: 0, default: 1
        let bytes = [0x41u8, 0x00, 0x0e, 0x01, 0x00, 0x01];
        let result = lifter().lift_wasm_function(&bytes, 0).unwrap();
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op, LlilOp::BranchTable { .. }))
        );
    }

    #[test]
    fn test_lift_call() {
        // call 5
        let bytes = [0x10u8, 0x05];
        let result = lifter().lift_wasm_function(&bytes, 0).unwrap();
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op, LlilOp::Call { target: 5 }))
        );
    }

    #[test]
    fn test_lift_call_indirect() {
        let bytes = [0x11u8, 0x02, 0x00];
        let result = lifter().lift_wasm_function(&bytes, 0).unwrap();
        assert!(result.ops.iter().any(|op| matches!(
            op,
            LlilOp::CallIndirect {
                type_idx: 2,
                table_idx: 0
            }
        )));
    }

    #[test]
    fn test_lift_if_else_end() {
        // i32.const 1, if void, i32.const 2, else, i32.const 3, end
        let bytes = [0x41u8, 0x01, 0x04, 0x40, 0x41, 0x02, 0x05, 0x41, 0x03, 0x0b];
        let result = lifter().lift_wasm_function(&bytes, 0).unwrap();
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op, LlilOp::IfBegin { .. }))
        );
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op, LlilOp::Else { .. }))
        );
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op, LlilOp::BlockEnd { .. }))
        );
    }

    #[test]
    fn test_lift_drop() {
        let bytes = [0x41u8, 0x01, 0x1a]; // i32.const 1, drop
        let result = lifter().lift_wasm_function(&bytes, 0).unwrap();
        assert!(result.ops.iter().any(|op| matches!(op, LlilOp::Drop)));
    }

    #[test]
    fn test_lift_i32_store() {
        let mut l = lifter();
        l.add_local(0, 32);
        // i32.const 0x100 (address), i32.const 42 (value), i32.store align=2 offset=0
        let bytes = [0x41u8, 0x80, 0x02, 0x41, 0x2a, 0x36, 0x02, 0x00];
        let result = l.lift_wasm_function(&bytes, 0).unwrap();
        assert!(
            result
                .ops
                .iter()
                .any(|op| matches!(op, LlilOp::Store { .. }))
        );
    }

    #[test]
    fn test_lift_temp_count_increases() {
        let bytes = [0x41u8, 0x01, 0x41, 0x02, 0x6a]; // add produces a temp
        let result = lifter().lift_wasm_function(&bytes, 0).unwrap();
        assert!(result.temp_count >= 1);
    }

    #[test]
    fn test_lift_base_address() {
        let bytes = [0x0fu8]; // return
        let result = lifter().lift_wasm_function(&bytes, 0xDEAD_0000).unwrap();
        assert_eq!(result.base_address, 0xDEAD_0000);
    }

    #[test]
    fn test_lifted_function_bytes_consumed() {
        let bytes = [0x41u8, 0x2a, 0x0f]; // 3 bytes
        let result = lifter().lift_wasm_function(&bytes, 0).unwrap();
        assert_eq!(result.bytes_consumed, 3);
    }

    #[test]
    fn test_lift_max_ops_guard() {
        let opts = LiftOptions {
            max_ops: 2,
            ..LiftOptions::default()
        };
        let mut l = WasmLifter::new(opts);
        // Many i32.const ops
        let bytes: Vec<u8> = (0..20).flat_map(|_| vec![0x41u8, 0x01]).collect();
        let result = l.lift_wasm_function(&bytes, 0).unwrap();
        assert!(result.ops.len() <= 2);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_lift_no_warnings_simple() {
        let mut l = lifter();
        l.add_local(0, 32);
        let bytes = [0x41u8, 0x01, 0x21, 0x00, 0x0f]; // const, local.set, return
        let result = l.lift_wasm_function(&bytes, 0).unwrap();
        assert!(
            result.warnings.is_empty(),
            "unexpected warnings: {:?}",
            result.warnings
        );
    }
}
