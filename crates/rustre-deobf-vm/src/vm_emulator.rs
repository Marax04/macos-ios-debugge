//! `vm_emulator` — Generic VM emulator for bytecode deobfuscation.
//!
//! Provides:
//! * [`VmEmulator`] — configurable interpreter for a custom VM's bytecode
//! * [`SemanticOp`] — record of a single semantically-meaningful operation
//! * [`EmulationTrace`] — ordered list of `SemanticOp`s from one emulation run
//! * Loop detection and handler summary generation
//!
//! The emulator does **not** depend on Unicorn or any native emulation library;
//! it operates on an abstract ISA described by a [`VmIsaConfig`] and a handler
//! dispatch table.  For true native emulation plug in the `unicorn_backend`
//! feature (not included here — this file provides the pure-Rust layer).


use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// SemanticOp — single recorded operation
// ─────────────────────────────────────────────────────────────────────────────

/// One semantically-meaningful operation recorded during emulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticOp {
    /// Push a value onto the VM stack.
    Push { value: u64 },
    /// Pop from the VM stack.
    Pop { value: u64 },
    /// Binary arithmetic/logic operation.
    BinOp {
        op: BinOpKind,
        lhs: u64,
        rhs: u64,
        result: u64,
    },
    /// Unary operation.
    UnaryOp { op: UnaryOpKind, operand: u64, result: u64 },
    /// Memory read: `value = mem[address]`.
    MemRead { address: u64, value: u64, width: u8 },
    /// Memory write: `mem[address] = value`.
    MemWrite { address: u64, value: u64, width: u8 },
    /// Register read (guest register file).
    RegRead { slot: u8, value: u64 },
    /// Register write (guest register file).
    RegWrite { slot: u8, value: u64 },
    /// Conditional branch: taken or not.
    Branch { condition: u64, taken: bool, target: u64 },
    /// Unconditional jump.
    Jump { target: u64 },
    /// Native call (leaves the VM context).
    NativeCall { address: u64 },
    /// VM halt / exit.
    Halt { exit_code: u64 },
    /// Unknown / unrecognized opcode.
    Unknown { opcode: u16 },
}

/// Binary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinOpKind {
    Add, Sub, Mul, UDiv, SDiv,
    And, Or, Xor,
    Shl, Shr, Sar, Rol, Ror,
    Cmp, Test,
}

impl std::fmt::Display for BinOpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Add => "ADD", Self::Sub => "SUB", Self::Mul => "MUL",
            Self::UDiv => "UDIV", Self::SDiv => "SDIV",
            Self::And => "AND", Self::Or => "OR", Self::Xor => "XOR",
            Self::Shl => "SHL", Self::Shr => "SHR", Self::Sar => "SAR",
            Self::Rol => "ROL", Self::Ror => "ROR",
            Self::Cmp => "CMP", Self::Test => "TEST",
        };
        write!(f, "{s}")
    }
}

/// Unary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnaryOpKind {
    Not, Neg, Bswap, Popcnt,
}

impl std::fmt::Display for UnaryOpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Not => write!(f, "NOT"),
            Self::Neg => write!(f, "NEG"),
            Self::Bswap => write!(f, "BSWAP"),
            Self::Popcnt => write!(f, "POPCNT"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EmulationTrace
// ─────────────────────────────────────────────────────────────────────────────

/// Ordered record of all [`SemanticOp`]s produced during one emulation run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulationTrace {
    pub ops: Vec<SemanticOp>,
    /// Total number of VM cycles executed (including repeated handlers).
    pub cycles: u64,
    /// Whether the trace was truncated due to a loop limit.
    pub truncated: bool,
    /// Whether the VM halted normally.
    pub halted: bool,
}

impl EmulationTrace {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an operation.
    pub fn push(&mut self, op: SemanticOp) {
        self.ops.push(op);
    }

    /// Count how many times a given opcode kind appears.
    #[must_use]
    pub fn count_op_kind(&self, kind: &str) -> usize {
        self.ops.iter().filter(|op| op_kind_name(op) == kind).count()
    }

    /// Return the sequence of net stack deltas (useful for stack-depth analysis).
    #[must_use]
    pub fn stack_deltas(&self) -> Vec<i32> {
        self.ops
            .iter()
            .map(|op| match op {
                SemanticOp::Push { .. } => 1,
                SemanticOp::Pop { .. } => -1,
                _ => 0,
            })
            .collect()
    }

    /// Identify the dominant operation (most frequent `BinOp` kind).
    #[must_use]
    pub fn dominant_binop(&self) -> Option<BinOpKind> {
        let mut counts: HashMap<BinOpKind, usize> = HashMap::with_capacity(15);
        for op in &self.ops {
            if let SemanticOp::BinOp { op: kind, .. } = op {
                *counts.entry(*kind).or_insert(0) += 1;
            }
        }
        counts.into_iter().max_by_key(|(_, c)| *c).map(|(k, _)| k)
    }
}

const fn op_kind_name(op: &SemanticOp) -> &'static str {
    match op {
        SemanticOp::Push { .. } => "Push",
        SemanticOp::Pop { .. } => "Pop",
        SemanticOp::BinOp { .. } => "BinOp",
        SemanticOp::UnaryOp { .. } => "UnaryOp",
        SemanticOp::MemRead { .. } => "MemRead",
        SemanticOp::MemWrite { .. } => "MemWrite",
        SemanticOp::RegRead { .. } => "RegRead",
        SemanticOp::RegWrite { .. } => "RegWrite",
        SemanticOp::Branch { .. } => "Branch",
        SemanticOp::Jump { .. } => "Jump",
        SemanticOp::NativeCall { .. } => "NativeCall",
        SemanticOp::Halt { .. } => "Halt",
        SemanticOp::Unknown { .. } => "Unknown",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler summary
// ─────────────────────────────────────────────────────────────────────────────

/// High-level semantic summary of a VM handler, derived from its trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerSummary {
    /// Address of the handler.
    pub address: u64,
    /// Inferred semantic name (e.g. `"ADD"`, `"LOAD"`, `"JCC"`).
    pub semantic: String,
    /// Stack depth change: +N = net push, −N = net pop.
    pub stack_delta: i32,
    /// Number of memory reads.
    pub mem_reads: u32,
    /// Number of memory writes.
    pub mem_writes: u32,
    /// Whether the handler can change control flow.
    pub has_branch: bool,
    /// Whether the handler makes a native call.
    pub has_native_call: bool,
    /// Dominant binary operation (if any).
    pub dominant_binop: Option<BinOpKind>,
    /// Confidence in the semantic classification.
    pub confidence: f32,
}

impl HandlerSummary {
    /// Derive a summary from an emulation trace.
    #[must_use]
    pub fn from_trace(address: u64, trace: &EmulationTrace) -> Self {
        let push_count = trace.count_op_kind("Push") as i32;
        let pop_count = trace.count_op_kind("Pop") as i32;
        let stack_delta = push_count - pop_count;
        let mem_reads = trace.count_op_kind("MemRead") as u32;
        let mem_writes = trace.count_op_kind("MemWrite") as u32;
        let has_branch = trace.count_op_kind("Branch") > 0 || trace.count_op_kind("Jump") > 0;
        let has_native_call = trace.count_op_kind("NativeCall") > 0;
        let dominant_binop = trace.dominant_binop();

        let (semantic, confidence) = infer_semantic(
            stack_delta,
            mem_reads,
            mem_writes,
            has_branch,
            has_native_call,
            dominant_binop,
        );

        Self {
            address,
            semantic,
            stack_delta,
            mem_reads,
            mem_writes,
            has_branch,
            has_native_call,
            dominant_binop,
            confidence,
        }
    }
}

fn infer_semantic(
    stack_delta: i32,
    mem_reads: u32,
    mem_writes: u32,
    has_branch: bool,
    has_native_call: bool,
    dominant_binop: Option<BinOpKind>,
) -> (String, f32) {
    if has_native_call {
        return ("CALL".into(), 0.80);
    }
    if has_branch && stack_delta == 0 {
        return ("JCC".into(), 0.75);
    }
    if has_branch && stack_delta <= -1 {
        return ("RET".into(), 0.70);
    }
    if mem_reads >= 1 && mem_writes == 0 && stack_delta >= 1 {
        return ("LOAD".into(), 0.72);
    }
    if mem_writes >= 1 && stack_delta <= -1 {
        return ("STORE".into(), 0.72);
    }
    if let Some(binop) = dominant_binop {
        let name = format!("{binop}");
        let conf = match binop {
            BinOpKind::Add | BinOpKind::Sub | BinOpKind::Xor
            | BinOpKind::And | BinOpKind::Or => 0.78,
            BinOpKind::Shl | BinOpKind::Shr | BinOpKind::Sar => 0.75,
            BinOpKind::Mul | BinOpKind::UDiv => 0.70,
            _ => 0.55,
        };
        return (name, conf);
    }
    if stack_delta >= 1 {
        return ("PUSH".into(), 0.60);
    }
    if stack_delta <= -1 {
        return ("POP".into(), 0.60);
    }
    ("NOP".into(), 0.40)
}

// ─────────────────────────────────────────────────────────────────────────────
// VM ISA configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Description of a handler's operation for the abstract emulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerSpec {
    /// Opcode identifier.
    pub opcode: u16,
    /// Semantic effect on the stack and registers.
    pub effect: HandlerEffect,
    /// Number of immediate bytes consumed from the bytecode stream.
    pub imm_bytes: u8,
}

/// Abstract effect of a handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandlerEffect {
    /// Push an immediate (read from bytecode).
    PushImm { width: u8 },
    /// Pop top of stack, discard.
    PopDiscard,
    /// Binary operation: pop two values, push result.
    BinaryOp(BinOpKind),
    /// Unary operation: pop one value, push result.
    UnaryOp(UnaryOpKind),
    /// Load: pop address, push value from mock memory.
    Load { width: u8 },
    /// Store: pop address and value, write to mock memory.
    Store { width: u8 },
    /// Conditional branch: pop condition.
    Branch,
    /// Unconditional jump.
    Jump,
    /// Call native (pop address, record call).
    Call,
    /// Halt execution.
    Halt,
    /// No operation.
    Nop,
}

/// Complete ISA configuration for the abstract emulator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmIsaConfig {
    /// Handler dispatch table.
    pub handlers: HashMap<u16, HandlerSpec>,
    /// Opcode byte width (1 or 2).
    pub opcode_width: u8,
    /// Whether the opcode is encrypted (simple XOR with a rolling key).
    pub encrypted: bool,
    /// XOR key seed for bytecode decryption (if `encrypted`).
    pub xor_key: u32,
}

impl VmIsaConfig {
    /// Create a new ISA config.
    #[must_use]
    pub fn new(opcode_width: u8) -> Self {
        Self {
            handlers: HashMap::new(),
            opcode_width,
            encrypted: false,
            xor_key: 0,
        }
    }

    /// Register a handler spec.
    pub fn register(&mut self, spec: HandlerSpec) {
        self.handlers.insert(spec.opcode, spec);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loop detection
// ─────────────────────────────────────────────────────────────────────────────

/// A loop detected during emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedLoop {
    /// Virtual address where the loop begins (back-edge target).
    pub loop_head: u64,
    /// Virtual address of the back-edge source.
    pub loop_tail: u64,
    /// Number of times the loop was observed in the trace.
    pub iteration_count: usize,
    /// Semantic ops inside one loop body.
    pub body_ops: Vec<String>,
}

/// Detect loops in a trace by looking for repeated jump targets.
#[must_use]
pub fn detect_loops(trace: &EmulationTrace) -> Vec<DetectedLoop> {
    let mut jump_history: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut results = Vec::new();

    for (i, op) in trace.ops.iter().enumerate() {
        if let SemanticOp::Jump { target } | SemanticOp::Branch { taken: true, target, .. } = op {
            jump_history.entry(*target).or_default().push(i);
        }
    }

    for (target, indices) in &jump_history {
        if indices.len() >= 2 {
            let first = indices[0];
            let last = *indices.last().unwrap();
            let slice = &trace.ops[first..last.min(first + 20)];
            let mut body_ops: Vec<String> = Vec::with_capacity(slice.len());
            body_ops.extend(slice.iter().map(|op| op_kind_name(op).to_string()));
            results.push(DetectedLoop {
                loop_head: *target,
                loop_tail: *target,
                iteration_count: indices.len(),
                body_ops,
            });
        }
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// VmEmulator
// ─────────────────────────────────────────────────────────────────────────────

/// Abstract VM emulator: interprets bytecode according to [`VmIsaConfig`].
pub struct VmEmulator {
    /// ISA configuration.
    pub isa: VmIsaConfig,
    /// Maximum number of emulation cycles before giving up.
    pub max_cycles: u64,
    /// Maximum loop iterations before aborting a loop.
    pub max_loop_iterations: u32,
    /// Mock memory (address → value byte).
    pub memory: HashMap<u64, u8>,
    /// Guest register file (slot → value).
    pub registers: [u64; 16],
    /// VM stack.
    pub stack: Vec<u64>,
    /// Current emulation trace.
    trace: EmulationTrace,
}

impl VmEmulator {
    /// Create a new emulator with the given ISA.
    #[must_use]
    pub fn new(isa: VmIsaConfig) -> Self {
        Self {
            isa,
            max_cycles: 10_000,
            max_loop_iterations: 64,
            memory: HashMap::new(),
            registers: [0u64; 16],
            stack: Vec::new(),
            trace: EmulationTrace::new(),
        }
    }

    #[must_use]
    pub const fn with_max_cycles(mut self, n: u64) -> Self {
        self.max_cycles = n;
        self
    }

    #[must_use]
    pub const fn with_max_loop_iterations(mut self, n: u32) -> Self {
        self.max_loop_iterations = n;
        self
    }

    /// Seed memory with initial values.
    pub fn seed_memory(&mut self, address: u64, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            if let Some(addr) = address.checked_add(i as u64) {
                self.memory.insert(addr, b);
            }
        }
    }

    /// Reset state for a fresh emulation run.
    pub fn reset(&mut self) {
        self.registers = [0u64; 16];
        self.stack.clear();
        self.trace = EmulationTrace::new();
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn stack_pop(&mut self) -> u64 {
        let v = self.stack.pop().unwrap_or(0);
        self.trace.push(SemanticOp::Pop { value: v });
        v
    }

    fn stack_push(&mut self, value: u64) {
        self.stack.push(value);
        self.trace.push(SemanticOp::Push { value });
    }

    fn mem_read(&mut self, address: u64, width: u8) -> u64 {
        let mut value = 0u64;
        for i in 0..u64::from(width) {
            let addr = address.saturating_add(i);
            let byte = self.memory.get(&addr).copied().unwrap_or(0xCC);
            value |= u64::from(byte) << (i * 8);
        }
        self.trace.push(SemanticOp::MemRead { address, value, width });
        value
    }

    fn mem_write(&mut self, address: u64, value: u64, width: u8) {
        for i in 0..u64::from(width) {
            let addr = address.saturating_add(i);
            self.memory.insert(addr, ((value >> (i * 8)) & 0xFF) as u8);
        }
        self.trace.push(SemanticOp::MemWrite { address, value, width });
    }

    const fn apply_binop(op: BinOpKind, lhs: u64, rhs: u64) -> u64 {
        match op {
            BinOpKind::Add => lhs.wrapping_add(rhs),
            BinOpKind::Sub => lhs.wrapping_sub(rhs),
            BinOpKind::Mul => lhs.wrapping_mul(rhs),
            BinOpKind::UDiv => if rhs != 0 { lhs / rhs } else { 0 },
            BinOpKind::SDiv => {
                if rhs != 0 {
                    ((lhs as i64).wrapping_div(rhs as i64)) as u64
                } else {
                    0
                }
            }
            BinOpKind::And | BinOpKind::Test => lhs & rhs,
            BinOpKind::Or => lhs | rhs,
            BinOpKind::Xor => lhs ^ rhs,
            BinOpKind::Shl => lhs.wrapping_shl(rhs as u32),
            BinOpKind::Shr => lhs.wrapping_shr(rhs as u32),
            BinOpKind::Sar => ((lhs as i64).wrapping_shr(rhs as u32)) as u64,
            BinOpKind::Rol => lhs.rotate_left(rhs as u32),
            BinOpKind::Ror => lhs.rotate_right(rhs as u32),
            BinOpKind::Cmp => (lhs as i64).wrapping_sub(rhs as i64) as u64,
            }
    }

    const fn apply_unary(op: UnaryOpKind, operand: u64) -> u64 {
        match op {
            UnaryOpKind::Not => !operand,
            UnaryOpKind::Neg => operand.wrapping_neg(),
            UnaryOpKind::Bswap => operand.swap_bytes(),
            UnaryOpKind::Popcnt => operand.count_ones() as u64,
        }
    }

    // ── Read next opcode from bytecode stream ─────────────────────────────────

    fn fetch_opcode(&self, bytecode: &[u8], ip: usize) -> Option<u16> {
        if self.isa.opcode_width == 2 {
            if ip + 2 > bytecode.len() {
                return None;
            }
            let raw = u16::from_le_bytes([bytecode[ip], bytecode[ip + 1]]);
            Some(if self.isa.encrypted {
                raw ^ (self.isa.xor_key as u16)
            } else {
                raw
            })
        } else {
            bytecode.get(ip).map(|&b| {
                let raw = u16::from(b);
                if self.isa.encrypted {
                    raw ^ (self.isa.xor_key as u16 & 0xFF)
                } else {
                    raw
                }
            })
        }
    }

    fn fetch_imm(&self, bytecode: &[u8], ip: usize, width: u8) -> u64 {
        let mut v = 0u64;
        for i in 0..width as usize {
            if let Some(&b) = bytecode.get(ip + i) {
                v |= u64::from(b) << (i * 8);
            }
        }
        v
    }

    // ── Main emulation loop ───────────────────────────────────────────────────

    /// Emulate `bytecode` from offset `entry_ip`.
    /// Returns the completed [`EmulationTrace`].
    pub fn emulate(&mut self, bytecode: &[u8], entry_ip: usize) -> EmulationTrace {
        self.reset();
        let mut ip = entry_ip;
        let opcode_step = self.isa.opcode_width as usize;

        // Loop detection: count visits per IP
        let mut ip_visit_count: HashMap<usize, u32> = HashMap::new();

        while self.trace.cycles < self.max_cycles {
            *ip_visit_count.entry(ip).or_insert(0) += 1;
            if ip_visit_count[&ip] > self.max_loop_iterations {
                self.trace.truncated = true;
                break;
            }

            let opcode = match self.fetch_opcode(bytecode, ip) {
                Some(o) => o,
                None => break,
            };

            ip += opcode_step;
            self.trace.cycles += 1;

            let spec = if let Some(s) = self.isa.handlers.get(&opcode).cloned() { s } else {
                self.trace.push(SemanticOp::Unknown { opcode });
                continue;
            };

            let imm = if spec.imm_bytes > 0 {
                let v = self.fetch_imm(bytecode, ip, spec.imm_bytes);
                ip += spec.imm_bytes as usize;
                v
            } else {
                0
            };

            match spec.effect.clone() {
                HandlerEffect::PushImm { width: _ } => {
                    self.stack_push(imm);
                }
                HandlerEffect::PopDiscard => {
                    let v = self.stack.pop().unwrap_or(0);
                    self.trace.push(SemanticOp::Pop { value: v });
                }
                HandlerEffect::BinaryOp(kind) => {
                    let rhs = self.stack_pop();
                    let lhs = self.stack_pop();
                    let result = Self::apply_binop(kind, lhs, rhs);
                    self.trace.push(SemanticOp::BinOp { op: kind, lhs, rhs, result });
                    self.stack.push(result);
                }
                HandlerEffect::UnaryOp(kind) => {
                    let operand = self.stack_pop();
                    let result = Self::apply_unary(kind, operand);
                    self.trace.push(SemanticOp::UnaryOp { op: kind, operand, result });
                    self.stack.push(result);
                }
                HandlerEffect::Load { width } => {
                    let addr = self.stack_pop();
                    let value = self.mem_read(addr, width);
                    self.stack_push(value);
                }
                HandlerEffect::Store { width } => {
                    let addr = self.stack_pop();
                    let value = self.stack_pop();
                    self.mem_write(addr, value, width);
                }
                HandlerEffect::Branch => {
                    let cond = self.stack_pop();
                    let target = imm;
                    let taken = cond != 0;
                    self.trace.push(SemanticOp::Branch { condition: cond, taken, target });
                    if taken {
                        // Jump to target (treat as offset from bytecode start)
                        let new_ip = target as usize;
                        if new_ip < bytecode.len() {
                            ip = new_ip;
                        } else {
                            break;
                        }
                    }
                }
                HandlerEffect::Jump => {
                    let target = self.stack_pop();
                    self.trace.push(SemanticOp::Jump { target });
                    let new_ip = target as usize;
                    if new_ip < bytecode.len() {
                        ip = new_ip;
                    } else {
                        break;
                    }
                }
                HandlerEffect::Call => {
                    let addr = self.stack_pop();
                    self.trace.push(SemanticOp::NativeCall { address: addr });
                    // Continue execution after the call
                }
                HandlerEffect::Halt => {
                    let code = self.stack.pop().unwrap_or(0);
                    self.trace.push(SemanticOp::Halt { exit_code: code });
                    self.trace.halted = true;
                    break;
                }
                HandlerEffect::Nop => {
                    // nothing
                }
            }
        }

        self.trace.clone()
    }

    // ── Handler summary generation ────────────────────────────────────────────

    /// Emulate a single handler body and return its summary.
    pub fn summarize_handler(&mut self, address: u64, bytecode: &[u8]) -> HandlerSummary {
        let trace = self.emulate(bytecode, 0);
        HandlerSummary::from_trace(address, &trace)
    }

    /// Emulate multiple handler bodies and return all summaries.
    pub fn summarize_handlers(
        &mut self,
        handlers: &[(u64, Vec<u8>)],
    ) -> Vec<HandlerSummary> {
        handlers
            .iter()
            .map(|(addr, body)| self.summarize_handler(*addr, body))
            .collect()
    }

    /// Return a reference to the current trace.
    #[must_use]
    pub const fn trace(&self) -> &EmulationTrace {
        &self.trace
    }

    /// Detect loops in the last emulation trace.
    #[must_use]
    pub fn detected_loops(&self) -> Vec<DetectedLoop> {
        detect_loops(&self.trace)
    }

    /// Count repeated handler sequences (patterns that appear 3+ times).
    #[must_use]
    pub fn repeated_patterns(&self) -> Vec<(Vec<String>, usize)> {
        find_repeated_subsequences(&self.trace.ops, 3, 8)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Repeated subsequence detection
// ─────────────────────────────────────────────────────────────────────────────

/// Find subsequences of `ops` of length 2..=`max_len` that appear at least
/// `min_count` times.  Returns `(pattern_op_names, count)`.
fn find_repeated_subsequences(
    ops: &[SemanticOp],
    min_count: usize,
    max_len: usize,
) -> Vec<(Vec<String>, usize)> {
    let names: Vec<&'static str> = ops.iter().map(op_kind_name).collect();
    let mut counts: HashMap<Vec<&'static str>, usize> = HashMap::new();

    for len in 2..=max_len.min(names.len()) {
        for window in names.windows(len) {
            *counts.entry(window.to_vec()).or_insert(0) += 1;
        }
    }

    let mut results: Vec<(Vec<String>, usize)> = counts
        .into_iter()
        .filter(|(_, c)| *c >= min_count)
        .map(|(k, c)| (k.into_iter().map(std::string::ToString::to_string).collect(), c))
        .collect();

    results.sort_by_key(|b| std::cmp::Reverse(b.1));
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_isa() -> VmIsaConfig {
        let mut isa = VmIsaConfig::new(1);

        // 0x01 = PUSH_IMM (4-byte immediate)
        isa.register(HandlerSpec {
            opcode: 0x01,
            effect: HandlerEffect::PushImm { width: 4 },
            imm_bytes: 4,
        });

        // 0x02 = ADD
        isa.register(HandlerSpec {
            opcode: 0x02,
            effect: HandlerEffect::BinaryOp(BinOpKind::Add),
            imm_bytes: 0,
        });

        // 0x03 = HALT
        isa.register(HandlerSpec {
            opcode: 0x03,
            effect: HandlerEffect::Halt,
            imm_bytes: 0,
        });

        // 0x04 = XOR
        isa.register(HandlerSpec {
            opcode: 0x04,
            effect: HandlerEffect::BinaryOp(BinOpKind::Xor),
            imm_bytes: 0,
        });

        // 0x05 = NOT
        isa.register(HandlerSpec {
            opcode: 0x05,
            effect: HandlerEffect::UnaryOp(UnaryOpKind::Not),
            imm_bytes: 0,
        });

        isa
    }

    #[test]
    fn test_push_add_halt() {
        let isa = minimal_isa();
        let mut emu = VmEmulator::new(isa);

        // PUSH 3, PUSH 4, ADD, HALT
        let bytecode = vec![
            0x01, 0x03, 0x00, 0x00, 0x00, // PUSH_IMM 3
            0x01, 0x04, 0x00, 0x00, 0x00, // PUSH_IMM 4
            0x02,                          // ADD
            0x03,                          // HALT
        ];

        let trace = emu.emulate(&bytecode, 0);
        assert!(trace.halted);

        // Stack should contain 7 after ADD
        let binop = trace.ops.iter().find(|op| matches!(op, SemanticOp::BinOp { .. }));
        assert!(binop.is_some());
        if let Some(SemanticOp::BinOp { result, .. }) = binop {
            assert_eq!(*result, 7);
        }
    }

    #[test]
    fn test_dominant_binop_xor() {
        let isa = minimal_isa();
        let mut emu = VmEmulator::new(isa);

        // PUSH 0xFF, PUSH 0x0F, XOR, PUSH 0xAA, PUSH 0x55, XOR, HALT
        let bytecode = vec![
            0x01, 0xFF, 0x00, 0x00, 0x00,
            0x01, 0x0F, 0x00, 0x00, 0x00,
            0x04,
            0x01, 0xAA, 0x00, 0x00, 0x00,
            0x01, 0x55, 0x00, 0x00, 0x00,
            0x04,
            0x03,
        ];

        let trace = emu.emulate(&bytecode, 0);
        assert_eq!(trace.dominant_binop(), Some(BinOpKind::Xor));
    }

    #[test]
    fn test_handler_summary_from_trace() {
        let mut trace = EmulationTrace::new();
        trace.push(SemanticOp::Push { value: 10 });
        trace.push(SemanticOp::Push { value: 5 });
        trace.push(SemanticOp::BinOp {
            op: BinOpKind::Sub,
            lhs: 10,
            rhs: 5,
            result: 5,
        });
        trace.push(SemanticOp::Push { value: 5 });

        let summary = HandlerSummary::from_trace(0x1000, &trace);
        assert_eq!(summary.semantic, "SUB");
        assert!(summary.confidence >= 0.7);
    }

    #[test]
    fn test_loop_detection() {
        let mut trace = EmulationTrace::new();
        let target = 0x200u64;
        for _ in 0..3 {
            trace.push(SemanticOp::Jump { target });
        }
        let loops = detect_loops(&trace);
        assert!(!loops.is_empty());
        assert_eq!(loops[0].loop_head, target);
        assert!(loops[0].iteration_count >= 3);
    }

    #[test]
    fn test_max_cycles_truncation() {
        let mut isa = VmIsaConfig::new(1);
        // NOP handler that never halts
        isa.register(HandlerSpec {
            opcode: 0x00,
            effect: HandlerEffect::Nop,
            imm_bytes: 0,
        });
        let mut emu = VmEmulator::new(isa).with_max_cycles(50);
        let bytecode = vec![0x00u8; 1000];
        let trace = emu.emulate(&bytecode, 0);
        assert!(trace.truncated || trace.cycles <= 50 + 1);
    }
}
