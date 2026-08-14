//! `taint_propagation_rules` — Comprehensive taint propagation transfer functions.
//!
//! Provides 50+ rules mapping LLIL-level operations to their taint transfer
//! semantics, including:
//! - Arithmetic operations (ADD, SUB, MUL, DIV propagate union)
//! - Bitwise AND: may sanitize when one operand is a known-zero constant
//! - XOR with a known mask: may narrow taint
//! - Shift operations: conservative union
//! - Memory load/store semantics
//! - Sanitizer detection (strlen → clean result, bcopy → propagate length)
//! - Phi-node (join) semantics

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{TaintExpr, TaintId, TaintInstr, TaintState, TaintedValue, eval_value, taint_bits};

/// Re-export of the lower-level taint evaluator so external callers can
/// directly query the taint of an expression alongside the rule engine.
pub use crate::eval_taint;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PropagationRuleError {
    #[error("rule not found for opcode: {0}")]
    RuleNotFound(String),
    #[error("invalid operand count: expected {expected}, got {got}")]
    InvalidOperandCount { expected: usize, got: usize },
    #[error("rule application failed: {0}")]
    ApplicationError(String),
}

// ─── OpClass ─────────────────────────────────────────────────────────────────

/// Broad classification of LLIL opcodes for rule lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpClass {
    /// Arithmetic: ADD, SUB, MUL, DIV, MOD.
    Arithmetic,
    /// Bitwise: AND, OR, XOR, NOT, SHL, SHR, SAR, ROL, ROR.
    Bitwise,
    /// Comparison: EQ, NE, LT, LE, GT, GE.
    Comparison,
    /// Memory: LOAD (read), STORE (write).
    Memory,
    /// Call: direct or indirect function call.
    Call,
    /// Return from function.
    Return,
    /// Register-to-register assignment.
    Assign,
    /// Phi node (join of multiple reaching definitions).
    Phi,
    /// Type extension: ZEXT, SEXT, TRUNC.
    Extension,
    /// Other / unknown.
    Other,
}

// ─── TaintTransferRule ────────────────────────────────────────────────────────

/// Describes how a single opcode transfers taint from inputs to output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintTransferRule {
    /// Canonical opcode name this rule applies to.
    pub opcode: String,
    /// Classification.
    pub class: OpClass,
    /// Human-readable description of the rule.
    pub description: String,
    /// The transfer function variant.
    pub transfer: TransferFn,
}

impl TaintTransferRule {
    /// Apply this rule to a list of input taint masks and optional
    /// concrete operand values, returning the output taint mask.
    #[must_use]
    pub fn apply(&self, inputs: &[TaintId], concrete_vals: &[u64]) -> TaintId {
        self.transfer.apply(inputs, concrete_vals)
    }
}

// ─── TransferFn ───────────────────────────────────────────────────────────────

/// The actual transfer function logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferFn {
    /// Output taint = union of all input taints.
    Union,
    /// Output taint = taint of first operand only.
    FirstOperand,
    /// Output taint = taint of second operand only.
    SecondOperand,
    /// Output is always clean.
    Clean,
    /// AND semantics: if one operand is concretely 0, result is clean.
    BitwiseAnd,
    /// XOR semantics: if both operands are identical symbolically, result is
    /// clean; otherwise union.
    BitwiseXor,
    /// OR semantics: if one operand is concretely all-ones, result is clean
    /// (constant); otherwise union.
    BitwiseOr,
    /// SHL by concrete amount: taint shifts into higher bits (union, conservative).
    ShiftLeft,
    /// SHR/SAR by concrete amount: taint shifts into lower bits (union, conservative).
    ShiftRight,
    /// Comparison: output is bool taint (union of operand taints).
    Comparison,
    /// Load: union of address taint and memory-cell taint.
    MemoryLoad,
    /// Sanitizer: output is always clean regardless of inputs.
    Sanitizer,
    /// Extension (ZEXT/SEXT/TRUNC): propagate taint from the single input.
    Extension,
    /// Phi join: union of all incoming taints.
    PhiJoin,
    /// Custom: use a named rule (looked up in the rule registry).
    Custom(String),
}

impl TransferFn {
    /// Apply the transfer function.
    #[must_use]
    pub fn apply(&self, inputs: &[TaintId], concrete_vals: &[u64]) -> TaintId {
        match self {
            TransferFn::Union => inputs.iter().fold(taint_bits::NONE, |acc, &t| acc | t),
            TransferFn::FirstOperand => inputs.first().copied().unwrap_or(taint_bits::NONE),
            TransferFn::SecondOperand => inputs.get(1).copied().unwrap_or(taint_bits::NONE),
            TransferFn::Clean | TransferFn::Sanitizer => taint_bits::NONE,

            TransferFn::BitwiseAnd => {
                // AND with concrete 0 → result is 0 (clean).
                // AND with concrete all-ones → result equals other operand.
                let lhs_taint = inputs.first().copied().unwrap_or(taint_bits::NONE);
                let rhs_taint = inputs.get(1).copied().unwrap_or(taint_bits::NONE);
                let lhs_val = concrete_vals.first().copied().unwrap_or(u64::MAX);
                let rhs_val = concrete_vals.get(1).copied().unwrap_or(u64::MAX);

                if lhs_val == 0 || rhs_val == 0 {
                    // x & 0 = 0 → clean
                    taint_bits::NONE
                } else if lhs_val == u64::MAX {
                    // 0xFFFF... & x = x → propagate rhs taint
                    rhs_taint
                } else if rhs_val == u64::MAX {
                    // x & 0xFFFF... = x → propagate lhs taint
                    lhs_taint
                } else {
                    // Conservative: union
                    lhs_taint | rhs_taint
                }
            }

            TransferFn::BitwiseXor => {
                let lhs_taint = inputs.first().copied().unwrap_or(taint_bits::NONE);
                let rhs_taint = inputs.get(1).copied().unwrap_or(taint_bits::NONE);
                let lhs_val = concrete_vals.first().copied();
                let rhs_val = concrete_vals.get(1).copied();

                // x XOR x = 0 → clean (self-XOR, idiom for zeroing)
                if lhs_val == rhs_val && lhs_val.is_some() {
                    return taint_bits::NONE;
                }
                // XOR with known mask: the output taint is limited to the
                // bits set in the mask (conservative: still union).
                lhs_taint | rhs_taint
            }

            TransferFn::BitwiseOr => {
                let lhs_taint = inputs.first().copied().unwrap_or(taint_bits::NONE);
                let rhs_taint = inputs.get(1).copied().unwrap_or(taint_bits::NONE);
                let lhs_val = concrete_vals.first().copied().unwrap_or(0);
                let rhs_val = concrete_vals.get(1).copied().unwrap_or(0);

                if lhs_val == u64::MAX || rhs_val == u64::MAX {
                    // OR with all-ones = all-ones → clean constant
                    taint_bits::NONE
                } else {
                    lhs_taint | rhs_taint
                }
            }

            TransferFn::ShiftLeft | TransferFn::ShiftRight => {
                // Conservative: union of operand taints.
                inputs.iter().fold(taint_bits::NONE, |acc, &t| acc | t)
            }

            TransferFn::Comparison => {
                // Comparison produces a boolean; taint is union of both operands.
                inputs.iter().fold(taint_bits::NONE, |acc, &t| acc | t)
            }

            TransferFn::MemoryLoad => {
                // Load: union of address taint and cell taint (handled externally).
                inputs.iter().fold(taint_bits::NONE, |acc, &t| acc | t)
            }

            TransferFn::Extension => inputs.first().copied().unwrap_or(taint_bits::NONE),

            TransferFn::PhiJoin => inputs.iter().fold(taint_bits::NONE, |acc, &t| acc | t),

            TransferFn::Custom(_) => {
                // Fall back to union for unrecognised custom rules.
                inputs.iter().fold(taint_bits::NONE, |acc, &t| acc | t)
            }
        }
    }
}

// ─── SanitizerSpec ────────────────────────────────────────────────────────────

/// Describes how a named function sanitizes its output taint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerSpec {
    /// Function name.
    pub name: String,
    /// Which argument positions are sanitized (empty = return value only).
    pub sanitizes_args: Vec<usize>,
    /// Whether the return value is always clean.
    pub return_is_clean: bool,
    /// Whether the sanitizer propagates length from a specific arg.
    pub propagates_length_from_arg: Option<usize>,
    /// Human-readable description.
    pub description: String,
}

impl SanitizerSpec {
    #[must_use]
    pub fn clean_return(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sanitizes_args: Vec::new(),
            return_is_clean: true,
            propagates_length_from_arg: None,
            description: description.into(),
        }
    }
}

// ─── PropagationRuleDb ────────────────────────────────────────────────────────

/// Registry of all taint propagation rules and sanitizer specs.
///
/// Look up a rule by exact opcode string or by [`OpClass`].
#[derive(Debug)]
pub struct PropagationRuleDb {
    rules: HashMap<String, TaintTransferRule>,
    sanitizers: HashMap<String, SanitizerSpec>,
    class_fallback: HashMap<OpClass, TransferFn>,
}

impl PropagationRuleDb {
    /// Create a new database pre-populated with all built-in rules.
    #[must_use]
    pub fn new() -> Self {
        let mut db = Self {
            rules: HashMap::new(),
            sanitizers: HashMap::new(),
            class_fallback: HashMap::new(),
        };
        db.populate_arithmetic_rules();
        db.populate_bitwise_rules();
        db.populate_comparison_rules();
        db.populate_memory_rules();
        db.populate_extension_rules();
        db.populate_misc_rules();
        db.populate_sanitizers();
        db.populate_class_fallbacks();
        db
    }

    /// Look up a rule by exact opcode name.
    #[must_use]
    pub fn get_rule(&self, opcode: &str) -> Option<&TaintTransferRule> {
        self.rules.get(opcode)
    }

    /// Look up a sanitizer spec by function name.
    #[must_use]
    pub fn get_sanitizer(&self, name: &str) -> Option<&SanitizerSpec> {
        self.sanitizers.get(name)
    }

    /// Apply the rule for `opcode` to `inputs` and `concrete_vals`.
    ///
    /// Falls back to the class fallback, then to full union.
    #[must_use]
    pub fn apply_rule(&self, opcode: &str, inputs: &[TaintId], concrete_vals: &[u64]) -> TaintId {
        if let Some(rule) = self.rules.get(opcode) {
            return rule.apply(inputs, concrete_vals);
        }
        // Try class fallback by class tag in opcode name.
        let class = opcode_to_class(opcode);
        if let Some(fallback) = self.class_fallback.get(&class) {
            return fallback.apply(inputs, concrete_vals);
        }
        // Full union (conservative).
        inputs.iter().fold(taint_bits::NONE, |acc, &t| acc | t)
    }

    /// Apply the transfer function for a `TaintExpr`.
    #[must_use]
    pub fn eval_expr_taint(&self, expr: &TaintExpr, state: &TaintState) -> TaintId {
        match expr {
            TaintExpr::Const(_) => taint_bits::NONE,
            TaintExpr::Reg(r) => state.reg_taint(r),
            TaintExpr::Load { addr, .. } => {
                let addr_taint = self.eval_expr_taint(addr, state);
                let addr_val = eval_value(addr, state);
                let mem_taint = state.mem_taint(addr_val);
                addr_taint | mem_taint
            }
            TaintExpr::Add(a, b) => {
                let ta = self.eval_expr_taint(a, state);
                let tb = self.eval_expr_taint(b, state);
                let va = eval_value(a, state);
                let vb = eval_value(b, state);
                self.apply_rule("ADD", &[ta, tb], &[va, vb])
            }
            TaintExpr::Sub(a, b) => {
                let ta = self.eval_expr_taint(a, state);
                let tb = self.eval_expr_taint(b, state);
                let va = eval_value(a, state);
                let vb = eval_value(b, state);
                self.apply_rule("SUB", &[ta, tb], &[va, vb])
            }
            TaintExpr::Mul(a, b) => {
                let ta = self.eval_expr_taint(a, state);
                let tb = self.eval_expr_taint(b, state);
                let va = eval_value(a, state);
                let vb = eval_value(b, state);
                self.apply_rule("MUL", &[ta, tb], &[va, vb])
            }
            TaintExpr::Div(a, b) => {
                let ta = self.eval_expr_taint(a, state);
                let tb = self.eval_expr_taint(b, state);
                let va = eval_value(a, state);
                let vb = eval_value(b, state);
                self.apply_rule("UDIV", &[ta, tb], &[va, vb])
            }
            TaintExpr::And(a, b) => {
                let ta = self.eval_expr_taint(a, state);
                let tb = self.eval_expr_taint(b, state);
                let va = eval_value(a, state);
                let vb = eval_value(b, state);
                self.apply_rule("AND", &[ta, tb], &[va, vb])
            }
            TaintExpr::Or(a, b) => {
                let ta = self.eval_expr_taint(a, state);
                let tb = self.eval_expr_taint(b, state);
                let va = eval_value(a, state);
                let vb = eval_value(b, state);
                self.apply_rule("OR", &[ta, tb], &[va, vb])
            }
            TaintExpr::Xor(a, b) => {
                let ta = self.eval_expr_taint(a, state);
                let tb = self.eval_expr_taint(b, state);
                let va = eval_value(a, state);
                let vb = eval_value(b, state);
                self.apply_rule("XOR", &[ta, tb], &[va, vb])
            }
            TaintExpr::Shl(a, b) => {
                let ta = self.eval_expr_taint(a, state);
                let tb = self.eval_expr_taint(b, state);
                self.apply_rule("SHL", &[ta, tb], &[])
            }
            TaintExpr::Shr(a, b) => {
                let ta = self.eval_expr_taint(a, state);
                let tb = self.eval_expr_taint(b, state);
                self.apply_rule("SHR", &[ta, tb], &[])
            }
            TaintExpr::Not(a) => {
                let ta = self.eval_expr_taint(a, state);
                self.apply_rule("NOT", &[ta], &[])
            }
            TaintExpr::Cmp(a, b) => {
                let ta = self.eval_expr_taint(a, state);
                let tb = self.eval_expr_taint(b, state);
                self.apply_rule("CMP", &[ta, tb], &[])
            }
        }
    }

    /// Apply the transfer function for a `TaintInstr`, updating `state`.
    /// Returns an optional description of a sanitizer that was applied.
    pub fn apply_instr_with_rules(
        &self,
        instr: &TaintInstr,
        state: &mut TaintState,
    ) -> Option<String> {
        match instr {
            TaintInstr::SetReg { reg, src, .. } => {
                let taint = self.eval_expr_taint(src, state);
                let value = eval_value(src, state);
                state.set_reg(reg, TaintedValue::new(value, taint));
                None
            }
            TaintInstr::Store { dest, val, .. } => {
                let addr_val = eval_value(dest, state);
                let val_taint = self.eval_expr_taint(val, state);
                let addr_taint = self.eval_expr_taint(dest, state);
                let combined = val_taint | addr_taint;
                let value = eval_value(val, state);
                state.set_mem(addr_val, TaintedValue::new(value, combined));
                None
            }
            TaintInstr::Call { target, args, .. } => {
                // Check for sanitizer.
                if let Some(san) = self.get_sanitizer(target) {
                    if san.return_is_clean {
                        state.set_reg("rax", TaintedValue::clean());
                        return Some(format!("sanitized by {}", san.name));
                    }
                    if let Some(arg_idx) = san.propagates_length_from_arg {
                        // e.g. bcopy: return value propagates length taint.
                        let len_taint = args
                            .get(arg_idx)
                            .map(|a| self.eval_expr_taint(a, state))
                            .unwrap_or(taint_bits::NONE);
                        state.set_reg("rax", TaintedValue::new(0, len_taint));
                        return Some(format!("length-propagated by {}", san.name));
                    }
                }
                None
            }
            TaintInstr::Return { val, .. } => {
                if let Some(v) = val {
                    let taint = self.eval_expr_taint(v, state);
                    state.set_reg("rax", TaintedValue::new(eval_value(v, state), taint));
                }
                None
            }
            TaintInstr::Branch { cond, addr } => {
                let taint = self.eval_expr_taint(cond, state);
                if taint_bits::is_tainted(taint) {
                    state.cf_taint.insert(*addr);
                }
                None
            }
            TaintInstr::Nop { .. } => None,
        }
    }

    /// Return the number of registered rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Return the number of registered sanitizers.
    #[must_use]
    pub fn sanitizer_count(&self) -> usize {
        self.sanitizers.len()
    }

    // ── Population helpers ────────────────────────────────────────────────────

    fn add_rule(&mut self, opcode: &str, class: OpClass, description: &str, transfer: TransferFn) {
        self.rules.insert(
            opcode.to_string(),
            TaintTransferRule {
                opcode: opcode.to_string(),
                class,
                description: description.to_string(),
                transfer,
            },
        );
    }

    fn populate_arithmetic_rules(&mut self) {
        // ADD/SUB/MUL: union of both operand taints.
        for op in &["ADD", "ADDI", "ADD64", "ADD32", "ADD16", "ADD8"] {
            self.add_rule(
                op,
                OpClass::Arithmetic,
                "ADD propagates union of operand taints",
                TransferFn::Union,
            );
        }
        for op in &["SUB", "SUBI", "SUB64", "SUB32", "SUB16", "SUB8"] {
            self.add_rule(
                op,
                OpClass::Arithmetic,
                "SUB propagates union of operand taints",
                TransferFn::Union,
            );
        }
        for op in &["MUL", "MULI", "MUL64", "MUL32", "IMUL", "IMUL32"] {
            self.add_rule(
                op,
                OpClass::Arithmetic,
                "MUL propagates union of operand taints",
                TransferFn::Union,
            );
        }
        // DIV/IDIV/MOD: union.
        for op in &["UDIV", "SDIV", "IDIV", "UREM", "SREM", "MOD", "IMOD"] {
            self.add_rule(
                op,
                OpClass::Arithmetic,
                "DIV/MOD propagates union of operand taints",
                TransferFn::Union,
            );
        }
        // NEG/ABS: propagate first operand.
        for op in &["NEG", "ABS", "NEG64", "NEG32"] {
            self.add_rule(
                op,
                OpClass::Arithmetic,
                "Unary arithmetic propagates operand taint",
                TransferFn::FirstOperand,
            );
        }
    }

    fn populate_bitwise_rules(&mut self) {
        // AND: may sanitize.
        for op in &["AND", "ANDI", "AND64", "AND32", "AND16", "AND8", "BAND"] {
            self.add_rule(
                op,
                OpClass::Bitwise,
                "AND may sanitize when one operand is 0",
                TransferFn::BitwiseAnd,
            );
        }
        // OR: may sanitize when one operand is all-ones.
        for op in &["OR", "ORI", "OR64", "OR32", "OR16", "OR8", "BOR"] {
            self.add_rule(
                op,
                OpClass::Bitwise,
                "OR may sanitize when one operand is all-ones",
                TransferFn::BitwiseOr,
            );
        }
        // XOR: self-XOR is 0 (clean); otherwise union.
        for op in &["XOR", "XORI", "XOR64", "XOR32", "XOR16", "XOR8", "BXOR"] {
            self.add_rule(
                op,
                OpClass::Bitwise,
                "XOR: self-XOR is clean, otherwise union",
                TransferFn::BitwiseXor,
            );
        }
        // NOT/BNOT: propagate.
        for op in &["NOT", "NOT64", "NOT32", "BNOT", "BITNOT"] {
            self.add_rule(
                op,
                OpClass::Bitwise,
                "Bitwise NOT propagates operand taint",
                TransferFn::FirstOperand,
            );
        }
        // Shifts.
        for op in &["SHL", "SAL", "SHL64", "SHL32", "SHL16", "LSL"] {
            self.add_rule(
                op,
                OpClass::Bitwise,
                "SHL: conservative union",
                TransferFn::ShiftLeft,
            );
        }
        for op in &["SHR", "SAR", "LSR", "SHR64", "SHR32", "ASHR"] {
            self.add_rule(
                op,
                OpClass::Bitwise,
                "SHR: conservative union",
                TransferFn::ShiftRight,
            );
        }
        // Rotate.
        for op in &["ROL", "ROR", "ROL64", "ROR64"] {
            self.add_rule(
                op,
                OpClass::Bitwise,
                "Rotate: union of operand taints",
                TransferFn::Union,
            );
        }
        // Byte-swap / bit-reverse.
        for op in &["BSWAP", "BSWAP16", "BSWAP32", "BSWAP64", "BITREVERSE"] {
            self.add_rule(
                op,
                OpClass::Bitwise,
                "BSWAP/BITREVERSE propagates operand taint",
                TransferFn::FirstOperand,
            );
        }
    }

    fn populate_comparison_rules(&mut self) {
        for op in &[
            "EQ", "NE", "LT", "LE", "GT", "GE", "ULT", "ULE", "UGT", "UGE", "SLT", "SLE", "SGT",
            "SGE", "CMP", "UCMP", "SCMP", "TEST", "UTEST",
        ] {
            self.add_rule(
                op,
                OpClass::Comparison,
                "Comparison result taint = union of operand taints",
                TransferFn::Comparison,
            );
        }
    }

    fn populate_memory_rules(&mut self) {
        // Load.
        for op in &[
            "LOAD",
            "LOAD8",
            "LOAD16",
            "LOAD32",
            "LOAD64",
            "LOAD_BYTE",
            "LOAD_WORD",
            "LOAD_DWORD",
            "LOAD_QWORD",
        ] {
            self.add_rule(
                op,
                OpClass::Memory,
                "LOAD: union of address taint and memory cell taint",
                TransferFn::MemoryLoad,
            );
        }
        // Store (result is the address; side effect tracked separately).
        for op in &["STORE", "STORE8", "STORE16", "STORE32", "STORE64"] {
            self.add_rule(
                op,
                OpClass::Memory,
                "STORE: propagate value taint to memory cell",
                TransferFn::Union,
            );
        }
    }

    fn populate_extension_rules(&mut self) {
        for op in &[
            "ZEXT", "SEXT", "TRUNC", "ZEXT8", "ZEXT16", "ZEXT32", "SEXT8", "SEXT16", "SEXT32",
            "TRUNC8", "TRUNC16", "TRUNC32",
        ] {
            self.add_rule(
                op,
                OpClass::Extension,
                "Extension/truncation propagates operand taint",
                TransferFn::Extension,
            );
        }
    }

    fn populate_misc_rules(&mut self) {
        // Assign / move.
        for op in &[
            "MOV", "MOVE", "SET", "COPY", "ASSIGN", "MOV64", "MOV32", "MOV16", "MOV8",
        ] {
            self.add_rule(
                op,
                OpClass::Assign,
                "Move/assign propagates source taint",
                TransferFn::FirstOperand,
            );
        }
        // Phi.
        for op in &["PHI", "JOIN", "MERGE"] {
            self.add_rule(
                op,
                OpClass::Phi,
                "Phi-node joins incoming taints via union",
                TransferFn::PhiJoin,
            );
        }
        // Constant load → clean.
        for op in &["CONST", "CONST_PTR", "FLOAT_CONST", "IMM"] {
            self.add_rule(
                op,
                OpClass::Other,
                "Constant is always clean",
                TransferFn::Clean,
            );
        }
        // Concat / extract.
        for op in &["CONCAT", "EXTRACT", "EXTRACT8", "EXTRACT16"] {
            self.add_rule(
                op,
                OpClass::Other,
                "Concat/extract propagates union of operand taints",
                TransferFn::Union,
            );
        }
        // System call.
        self.add_rule(
            "SYSCALL",
            OpClass::Other,
            "System call: conservative union of all arg taints",
            TransferFn::Union,
        );
        // NOP / fence.
        for op in &["NOP", "FENCE", "BARRIER"] {
            self.add_rule(
                op,
                OpClass::Other,
                "NOP: output is clean",
                TransferFn::Clean,
            );
        }
        // Unimplemented / intrinsic.
        self.add_rule(
            "INTRINSIC",
            OpClass::Other,
            "Intrinsic: conservative union",
            TransferFn::Union,
        );
    }

    fn populate_sanitizers(&mut self) {
        // strlen: reads from src, returns a length (always clean w.r.t. content).
        self.sanitizers.insert(
            "strlen".into(),
            SanitizerSpec::clean_return("strlen", "strlen result is a safe length, not user data"),
        );
        self.sanitizers.insert(
            "strnlen".into(),
            SanitizerSpec::clean_return("strnlen", "strnlen result is a safe length"),
        );
        self.sanitizers.insert(
            "wcslen".into(),
            SanitizerSpec::clean_return("wcslen", "wcslen result is a safe length"),
        );

        // Hash functions → clean return.
        for name in &[
            "md5", "sha1", "sha256", "sha512", "crc32", "crc16", "checksum",
        ] {
            self.sanitizers.insert(
                name.to_string(),
                SanitizerSpec::clean_return(
                    *name,
                    "hash function output is derived, not directly tainted data",
                ),
            );
        }

        // Validated input parsing → clean.
        for name in &[
            "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull", "strtod", "strtof",
        ] {
            self.sanitizers.insert(
                name.to_string(),
                SanitizerSpec::clean_return(*name, "numeric parser sanitizes to integer"),
            );
        }

        // bcopy(src, dst, n): propagates length from arg2.
        self.sanitizers.insert(
            "bcopy".into(),
            SanitizerSpec {
                name: "bcopy".into(),
                sanitizes_args: Vec::new(),
                return_is_clean: false,
                propagates_length_from_arg: Some(2),
                description: "bcopy propagates length taint".into(),
            },
        );

        // escape_string / html_escape → clean output.
        for name in &[
            "escape_string",
            "html_escape",
            "url_encode",
            "html_entities",
            "sanitize",
            "validate_input",
            "filter_input",
            "mysql_real_escape_string",
            "pg_escape_string",
            "sqlite3_mprintf", // produces sanitised SQL
        ] {
            self.sanitizers.insert(
                name.to_string(),
                SanitizerSpec::clean_return(*name, "escaping/sanitization function"),
            );
        }
    }

    fn populate_class_fallbacks(&mut self) {
        self.class_fallback
            .insert(OpClass::Arithmetic, TransferFn::Union);
        self.class_fallback
            .insert(OpClass::Bitwise, TransferFn::Union);
        self.class_fallback
            .insert(OpClass::Comparison, TransferFn::Comparison);
        self.class_fallback
            .insert(OpClass::Memory, TransferFn::MemoryLoad);
        self.class_fallback.insert(OpClass::Call, TransferFn::Union);
        self.class_fallback
            .insert(OpClass::Return, TransferFn::FirstOperand);
        self.class_fallback
            .insert(OpClass::Assign, TransferFn::FirstOperand);
        self.class_fallback
            .insert(OpClass::Phi, TransferFn::PhiJoin);
        self.class_fallback
            .insert(OpClass::Extension, TransferFn::Extension);
        self.class_fallback
            .insert(OpClass::Other, TransferFn::Union);
    }
}

impl Default for PropagationRuleDb {
    fn default() -> Self {
        Self::new()
    }
}

/// Map an opcode name to an [`OpClass`] by keyword matching.
fn opcode_to_class(opcode: &str) -> OpClass {
    let op = opcode.to_uppercase();
    if op.contains("LOAD") {
        return OpClass::Memory;
    }
    if op.contains("STORE") {
        return OpClass::Memory;
    }
    if op.contains("ADD")
        || op.contains("SUB")
        || op.contains("MUL")
        || op.contains("DIV")
        || op.contains("MOD")
        || op.contains("NEG")
    {
        return OpClass::Arithmetic;
    }
    if op.contains("AND")
        || op.contains("OR")
        || op.contains("XOR")
        || op.contains("NOT")
        || op.contains("SHL")
        || op.contains("SHR")
        || op.contains("ROL")
        || op.contains("ROR")
        || op.contains("BSWAP")
    {
        return OpClass::Bitwise;
    }
    if op.contains("EQ")
        || op.contains("NE")
        || op.contains("LT")
        || op.contains("GT")
        || op.contains("LE")
        || op.contains("GE")
        || op.contains("CMP")
        || op.contains("TEST")
    {
        return OpClass::Comparison;
    }
    if op.contains("PHI") || op.contains("JOIN") {
        return OpClass::Phi;
    }
    if op.contains("ZEXT") || op.contains("SEXT") || op.contains("TRUNC") {
        return OpClass::Extension;
    }
    if op.contains("MOV") || op.contains("COPY") || op.contains("SET") {
        return OpClass::Assign;
    }
    OpClass::Other
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TaintState;

    fn db() -> PropagationRuleDb {
        PropagationRuleDb::new()
    }

    #[test]
    fn test_rule_db_populated() {
        let d = db();
        assert!(
            d.rule_count() >= 50,
            "expected >= 50 rules, got {}",
            d.rule_count()
        );
    }

    #[test]
    fn test_sanitizer_count() {
        let d = db();
        assert!(d.sanitizer_count() >= 10, "expected >= 10 sanitizers");
    }

    #[test]
    fn test_add_rule_union() {
        let d = db();
        let result = d.apply_rule(
            "ADD",
            &[taint_bits::USER_INPUT, taint_bits::NETWORK],
            &[1, 2],
        );
        assert_eq!(result, taint_bits::USER_INPUT | taint_bits::NETWORK);
    }

    #[test]
    fn test_and_sanitize_zero_lhs() {
        let d = db();
        // AND with concrete 0 → clean.
        let result = d.apply_rule(
            "AND",
            &[taint_bits::USER_INPUT, taint_bits::NETWORK],
            &[0, 0xFF],
        );
        assert_eq!(result, taint_bits::NONE);
    }

    #[test]
    fn test_and_sanitize_zero_rhs() {
        let d = db();
        let result = d.apply_rule("AND", &[taint_bits::NETWORK, taint_bits::FILE], &[0xFF, 0]);
        assert_eq!(result, taint_bits::NONE);
    }

    #[test]
    fn test_and_all_ones_lhs_propagates_rhs() {
        let d = db();
        let result = d.apply_rule(
            "AND",
            &[taint_bits::NETWORK, taint_bits::FILE],
            &[u64::MAX, 0x42],
        );
        assert_eq!(result, taint_bits::FILE);
    }

    #[test]
    fn test_xor_self_is_clean() {
        let d = db();
        let val = 0xDEAD_u64;
        let result = d.apply_rule(
            "XOR",
            &[taint_bits::USER_INPUT, taint_bits::USER_INPUT],
            &[val, val],
        );
        assert_eq!(result, taint_bits::NONE);
    }

    #[test]
    fn test_or_all_ones_sanitizes() {
        let d = db();
        let result = d.apply_rule(
            "OR",
            &[taint_bits::NETWORK, taint_bits::FILE],
            &[u64::MAX, 42],
        );
        assert_eq!(result, taint_bits::NONE);
    }

    #[test]
    fn test_shift_left_union() {
        let d = db();
        let result = d.apply_rule("SHL", &[taint_bits::USER_INPUT, taint_bits::NONE], &[]);
        assert_eq!(result, taint_bits::USER_INPUT);
    }

    #[test]
    fn test_comparison_union() {
        let d = db();
        let result = d.apply_rule("CMP", &[taint_bits::FILE, taint_bits::REGISTRY], &[]);
        assert_eq!(result, taint_bits::FILE | taint_bits::REGISTRY);
    }

    #[test]
    fn test_mov_first_operand() {
        let d = db();
        let result = d.apply_rule("MOV", &[taint_bits::NETWORK, taint_bits::NONE], &[]);
        assert_eq!(result, taint_bits::NETWORK);
    }

    #[test]
    fn test_const_is_clean() {
        let d = db();
        let result = d.apply_rule("CONST", &[taint_bits::USER_INPUT], &[42]);
        assert_eq!(result, taint_bits::NONE);
    }

    #[test]
    fn test_strlen_sanitizer_present() {
        let d = db();
        let spec = d.get_sanitizer("strlen").unwrap();
        assert!(spec.return_is_clean);
    }

    #[test]
    fn test_bcopy_propagates_length() {
        let d = db();
        let spec = d.get_sanitizer("bcopy").unwrap();
        assert!(!spec.return_is_clean);
        assert_eq!(spec.propagates_length_from_arg, Some(2));
    }

    #[test]
    fn test_atoi_sanitizer() {
        let d = db();
        let spec = d.get_sanitizer("atoi").unwrap();
        assert!(spec.return_is_clean);
    }

    #[test]
    fn test_eval_expr_taint_add_with_rules() {
        let d = db();
        let mut state = TaintState::new();
        state.taint_reg("rax", taint_bits::USER_INPUT);
        let expr = TaintExpr::Add(
            Box::new(TaintExpr::Reg("rax".into())),
            Box::new(TaintExpr::Const(1)),
        );
        let t = d.eval_expr_taint(&expr, &state);
        assert_eq!(t, taint_bits::USER_INPUT);
    }

    #[test]
    fn test_eval_expr_taint_and_sanitize() {
        let d = db();
        let mut state = TaintState::new();
        state.set_reg("rax", TaintedValue::new(0xFF, taint_bits::NETWORK));
        let expr = TaintExpr::And(
            Box::new(TaintExpr::Reg("rax".into())),
            Box::new(TaintExpr::Const(0)), // AND with 0 sanitizes
        );
        let t = d.eval_expr_taint(&expr, &state);
        assert_eq!(t, taint_bits::NONE);
    }

    #[test]
    fn test_apply_instr_setreg() {
        let d = db();
        let mut state = TaintState::new();
        state.taint_reg("rdi", taint_bits::USER_INPUT);
        let instr = TaintInstr::SetReg {
            reg: "rax".into(),
            src: TaintExpr::Reg("rdi".into()),
            addr: 0x100,
        };
        d.apply_instr_with_rules(&instr, &mut state);
        assert_eq!(state.reg_taint("rax"), taint_bits::USER_INPUT);
    }

    #[test]
    fn test_apply_instr_sanitizer_strlen() {
        let d = db();
        let mut state = TaintState::new();
        state.taint_reg("rdi", taint_bits::NETWORK);
        let instr = TaintInstr::Call {
            target: "strlen".into(),
            args: vec![TaintExpr::Reg("rdi".into())],
            addr: 0x200,
        };
        let result = d.apply_instr_with_rules(&instr, &mut state);
        // Return value rax should be clean.
        assert_eq!(state.reg_taint("rax"), taint_bits::NONE);
        assert!(result.is_some());
    }

    #[test]
    fn test_not_rule_propagates() {
        let d = db();
        let result = d.apply_rule("NOT", &[taint_bits::FILE], &[0xFF]);
        assert_eq!(result, taint_bits::FILE);
    }

    #[test]
    fn test_phi_join() {
        let d = db();
        let result = d.apply_rule(
            "PHI",
            &[
                taint_bits::USER_INPUT,
                taint_bits::REGISTRY,
                taint_bits::NONE,
            ],
            &[],
        );
        assert_eq!(result, taint_bits::USER_INPUT | taint_bits::REGISTRY);
    }

    #[test]
    fn test_extension_propagates() {
        let d = db();
        let result = d.apply_rule("ZEXT", &[taint_bits::COMMAND_LINE], &[]);
        assert_eq!(result, taint_bits::COMMAND_LINE);
    }

    #[test]
    fn test_unknown_opcode_falls_back_to_union() {
        let d = db();
        let result = d.apply_rule(
            "UNKNOWN_OP_XYZ",
            &[taint_bits::FILE, taint_bits::NETWORK],
            &[],
        );
        assert_eq!(result, taint_bits::FILE | taint_bits::NETWORK);
    }
}
