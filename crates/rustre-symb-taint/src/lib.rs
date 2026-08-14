//! `rustre-symb-taint` — taint analysis for symbolic execution.
//!
//! Full taint engine with bitmask sources, per-register/memory state,
//! LLIL transfer functions, dangerous sink detection, and inter-procedural
//! summaries.

pub mod data_flow_tracker;
pub mod dataflow_taint;
pub mod heap_taint;
pub mod interprocedural;
pub mod taint_policy;
pub mod taint_propagation_rules;
pub mod taint_report_extended;
pub mod taint_sinks;
pub mod vuln_reporter;
pub mod taint_sinks_full;
pub mod taint_propagator;
pub mod taint_sink_detector;
pub mod taint_summary;
pub mod taint_graph;
pub mod sanitizer_detector;
pub mod taint_report_generator;

use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TaintError {
    #[error("taint source not found: {0}")]
    SourceNotFound(String),
    #[error("analysis error: {0}")]
    AnalysisError(String),
    #[error("cycle detected in taint graph")]
    CycleDetected,
    #[error("{0}")]
    Other(String),
}

// ─── TaintId bitmask ──────────────────────────────────────────────────────────
//
// TaintId: u64 bitmask (64 possible taint sources).
// Bit 0 = user_input, 1 = network, 2 = file, 3 = environment,
// 4 = command_line, 5 = registry, 6..63 = custom.

pub type TaintId = u64;

pub mod taint_bits {
    pub const USER_INPUT: u64 = 1 << 0;
    pub const NETWORK: u64 = 1 << 1;
    pub const FILE: u64 = 1 << 2;
    pub const ENVIRONMENT: u64 = 1 << 3;
    pub const COMMAND_LINE: u64 = 1 << 4;
    pub const REGISTRY: u64 = 1 << 5;
    pub const CUSTOM_BASE: u64 = 1 << 6;
    pub const NONE: u64 = 0;
    pub const ALL: u64 = u64::MAX;

    pub fn custom(idx: u8) -> u64 {
        if idx < 58 { 1 << (6 + idx) } else { 0 }
    }
    pub fn is_tainted(mask: u64) -> bool {
        mask != 0
    }
    pub fn union(a: u64, b: u64) -> u64 {
        a | b
    }
    pub fn intersect(a: u64, b: u64) -> u64 {
        a & b
    }
    pub fn has_bit(mask: u64, bit: u64) -> bool {
        mask & bit != 0
    }
}

// ─── TaintSource (named) ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintSourceDef {
    pub id: TaintId,
    pub name: String,
    pub description: String,
}

impl TaintSourceDef {
    pub fn new(id: TaintId, name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            description: description.into(),
        }
    }
    pub fn user_input() -> Self {
        Self::new(taint_bits::USER_INPUT, "user_input", "Direct user input")
    }
    pub fn network() -> Self {
        Self::new(taint_bits::NETWORK, "network", "Network socket data")
    }
    pub fn file() -> Self {
        Self::new(taint_bits::FILE, "file", "File read data")
    }
    pub fn environment() -> Self {
        Self::new(
            taint_bits::ENVIRONMENT,
            "environment",
            "Environment variable",
        )
    }
    pub fn command_line() -> Self {
        Self::new(
            taint_bits::COMMAND_LINE,
            "command_line",
            "Command-line argument",
        )
    }
    pub fn registry() -> Self {
        Self::new(taint_bits::REGISTRY, "registry", "Windows registry value")
    }
}

// ─── TaintedValue ─────────────────────────────────────────────────────────────

/// A concrete value with an attached taint mask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintedValue {
    /// Concrete value (or symbolic placeholder).
    pub value: u64,
    /// Bitmask of taint sources.
    pub taints: TaintId,
}

impl TaintedValue {
    pub const CLEAN: Self = Self {
        value: 0,
        taints: taint_bits::NONE,
    };

    #[must_use]
    pub fn new(value: u64, taints: TaintId) -> Self {
        Self { value, taints }
    }
    #[must_use]
    pub fn tainted(value: u64, source: TaintId) -> Self {
        Self {
            value,
            taints: source,
        }
    }
    #[must_use]
    pub fn is_tainted(&self) -> bool {
        taint_bits::is_tainted(self.taints)
    }
    #[must_use]
    pub fn clean() -> Self {
        Self::CLEAN
    }
    #[must_use]
    pub fn union_taints(&self, other: &Self) -> TaintId {
        self.taints | other.taints
    }
}

impl Default for TaintedValue {
    fn default() -> Self {
        Self::CLEAN
    }
}

// ─── Register IDs ─────────────────────────────────────────────────────────────

pub type RegId = String;

// ─── TaintState ───────────────────────────────────────────────────────────────

/// Complete taint state: registers, flat memory, stack.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintState {
    /// Register → TaintedValue
    pub registers: HashMap<RegId, TaintedValue>,
    /// Flat memory address → TaintedValue
    pub memory: HashMap<u64, TaintedValue>,
    /// Stack offsets (signed, rbp-relative) → TaintedValue
    pub stack_taints: BTreeMap<i64, TaintedValue>,
    /// Instruction tick counter.
    pub current_ticks: u64,
    /// Control-flow taint: set of addresses where branch condition is tainted.
    pub cf_taint: HashSet<u64>,
    /// Address of the most recently applied LLIL instruction, useful for
    /// attributing later findings to the instruction that caused the change.
    pub last_pc: u64,
}

impl TaintState {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Register operations ─────────────────────────────────────────────────

    pub fn get_reg(&self, reg: &str) -> TaintedValue {
        self.registers.get(reg).cloned().unwrap_or_default()
    }
    pub fn set_reg(&mut self, reg: &str, val: TaintedValue) {
        self.registers.insert(reg.to_string(), val);
    }
    pub fn taint_reg(&mut self, reg: &str, source: TaintId) {
        let v = self.registers.entry(reg.to_string()).or_default();
        v.taints |= source;
    }
    pub fn sanitize_register(&mut self, reg: &str) {
        if let Some(v) = self.registers.get_mut(reg) {
            v.taints = taint_bits::NONE;
        }
    }
    pub fn reg_taint(&self, reg: &str) -> TaintId {
        self.registers
            .get(reg)
            .map(|v| v.taints)
            .unwrap_or(taint_bits::NONE)
    }

    // ── Memory operations ──────────────────────────────────────────────────

    pub fn get_mem(&self, addr: u64) -> TaintedValue {
        self.memory.get(&addr).cloned().unwrap_or_default()
    }
    pub fn set_mem(&mut self, addr: u64, val: TaintedValue) {
        self.memory.insert(addr, val);
    }
    pub fn mark_tainted(&mut self, addr: u64, size: usize, source_id: TaintId) {
        // Cap size to a sane limit (1 MiB) to prevent unbounded loop when the
        // caller supplies a huge or attacker-controlled size value.
        let capped = size.min(1 << 20);
        for i in 0..capped as u64 {
            let entry = self.memory.entry(addr + i).or_default();
            entry.taints |= source_id;
        }
    }
    pub fn sanitize_memory(&mut self, addr: u64, size: usize) {
        let capped = size.min(1 << 20);
        for i in 0..capped as u64 {
            if let Some(v) = self.memory.get_mut(&(addr + i)) {
                v.taints = taint_bits::NONE;
            }
        }
    }
    pub fn mem_taint(&self, addr: u64) -> TaintId {
        self.memory
            .get(&addr)
            .map(|v| v.taints)
            .unwrap_or(taint_bits::NONE)
    }

    // ── Stack operations ───────────────────────────────────────────────────

    pub fn get_stack(&self, offset: i64) -> TaintedValue {
        self.stack_taints.get(&offset).cloned().unwrap_or_default()
    }
    pub fn set_stack(&mut self, offset: i64, val: TaintedValue) {
        self.stack_taints.insert(offset, val);
    }
    pub fn stack_taint(&self, offset: i64) -> TaintId {
        self.stack_taints
            .get(&offset)
            .map(|v| v.taints)
            .unwrap_or(taint_bits::NONE)
    }
}

// ─── LLIL-level Transfer Functions ────────────────────────────────────────────
//
// Propagation rules for each LLIL op:
//   SetReg(r, expr): result_taint = union of all operand taints
//   GetReg(r): return register's taint
//   Add/Sub/Mul/Div/And/Or/Xor/Not/Shl/Shr: result = union of operand taints
//   Load(addr): result = taint(addr) | taint(memory[eval(addr)])
//   Store(addr, val): memory[eval(addr)].taints |= taint(val) | taint(addr)
//   Compare: propagate to condition, track as control-flow taint

/// Simplified LLIL expression representation for taint transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaintExpr {
    Const(u64),
    Reg(String),
    Load { addr: Box<TaintExpr>, size: usize },
    Add(Box<TaintExpr>, Box<TaintExpr>),
    Sub(Box<TaintExpr>, Box<TaintExpr>),
    Mul(Box<TaintExpr>, Box<TaintExpr>),
    Div(Box<TaintExpr>, Box<TaintExpr>),
    And(Box<TaintExpr>, Box<TaintExpr>),
    Or(Box<TaintExpr>, Box<TaintExpr>),
    Xor(Box<TaintExpr>, Box<TaintExpr>),
    Not(Box<TaintExpr>),
    Shl(Box<TaintExpr>, Box<TaintExpr>),
    Shr(Box<TaintExpr>, Box<TaintExpr>),
    Cmp(Box<TaintExpr>, Box<TaintExpr>),
}

/// LLIL instruction for taint propagation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaintInstr {
    SetReg {
        reg: String,
        src: TaintExpr,
        addr: u64,
    },
    Store {
        dest: TaintExpr,
        val: TaintExpr,
        addr: u64,
    },
    Call {
        target: String,
        args: Vec<TaintExpr>,
        addr: u64,
    },
    Return {
        val: Option<TaintExpr>,
        addr: u64,
    },
    Branch {
        cond: TaintExpr,
        addr: u64,
    },
    Nop {
        addr: u64,
    },
}

/// Evaluate the taint mask of an expression given current state.
pub fn eval_taint(expr: &TaintExpr, state: &TaintState) -> TaintId {
    match expr {
        TaintExpr::Const(_) => taint_bits::NONE,
        TaintExpr::Reg(r) => state.reg_taint(r),
        TaintExpr::Load { addr, .. } => {
            let addr_taint = eval_taint(addr, state);
            let addr_val = eval_value(addr, state);
            let mem_taint = state.mem_taint(addr_val);
            taint_bits::union(addr_taint, mem_taint)
        }
        TaintExpr::Add(a, b)
        | TaintExpr::Sub(a, b)
        | TaintExpr::Mul(a, b)
        | TaintExpr::Div(a, b)
        | TaintExpr::Or(a, b)
        | TaintExpr::Xor(a, b)
        | TaintExpr::Shl(a, b)
        | TaintExpr::Shr(a, b)
        | TaintExpr::Cmp(a, b) => taint_bits::union(eval_taint(a, state), eval_taint(b, state)),
        TaintExpr::And(a, b) => {
            // AND with constant 0 sanitizes; conservative: union anyway
            taint_bits::union(eval_taint(a, state), eval_taint(b, state))
        }
        TaintExpr::Not(a) => eval_taint(a, state),
    }
}

/// Evaluate the concrete value of an expression (best-effort).
pub fn eval_value(expr: &TaintExpr, state: &TaintState) -> u64 {
    match expr {
        TaintExpr::Const(v) => *v,
        TaintExpr::Reg(r) => state.get_reg(r).value,
        TaintExpr::Load { addr, .. } => {
            let a = eval_value(addr, state);
            state.get_mem(a).value
        }
        TaintExpr::Add(a, b) => eval_value(a, state).wrapping_add(eval_value(b, state)),
        TaintExpr::Sub(a, b) => eval_value(a, state).wrapping_sub(eval_value(b, state)),
        TaintExpr::Mul(a, b) => eval_value(a, state).wrapping_mul(eval_value(b, state)),
        TaintExpr::And(a, b) => eval_value(a, state) & eval_value(b, state),
        TaintExpr::Or(a, b) => eval_value(a, state) | eval_value(b, state),
        TaintExpr::Xor(a, b) => eval_value(a, state) ^ eval_value(b, state),
        TaintExpr::Shl(a, b) => eval_value(a, state) << (eval_value(b, state) & 63),
        TaintExpr::Shr(a, b) => eval_value(a, state) >> (eval_value(b, state) & 63),
        TaintExpr::Not(a) => !eval_value(a, state),
        TaintExpr::Div(a, b) => {
            let bv = eval_value(b, state);
            if bv == 0 {
                0
            } else {
                eval_value(a, state) / bv
            }
        }
        TaintExpr::Cmp(_, _) => 0,
    }
}

/// Apply a single LLIL instruction to the taint state. Returns any sink finding.
pub fn apply_instr(instr: &TaintInstr, state: &mut TaintState) -> Option<TaintFinding> {
    state.current_ticks += 1;
    match instr {
        TaintInstr::SetReg { reg, src, addr } => {
            let taint = eval_taint(src, state);
            let value = eval_value(src, state);
            state.set_reg(reg, TaintedValue::new(value, taint));
            state.last_pc = *addr;
            None
        }
        TaintInstr::Store { dest, val, addr } => {
            let addr_val = eval_value(dest, state);
            let val_taint = eval_taint(val, state);
            let addr_taint = eval_taint(dest, state);
            let combined = taint_bits::union(val_taint, addr_taint);
            let value = eval_value(val, state);
            state.set_mem(addr_val, TaintedValue::new(value, combined));
            // Also track on stack if it's stack-relative
            state.last_pc = *addr;
            None
        }
        TaintInstr::Call { target, args, addr } => check_dangerous_sink(target, args, state, *addr),
        TaintInstr::Branch { cond, addr } => {
            let taint = eval_taint(cond, state);
            if taint_bits::is_tainted(taint) {
                state.cf_taint.insert(*addr);
            }
            None
        }
        TaintInstr::Return { val, addr } => {
            if let Some(v) = val {
                let taint = eval_taint(v, state);
                state.set_reg("rax", TaintedValue::new(eval_value(v, state), taint));
            }
            state.last_pc = *addr;
            None
        }
        TaintInstr::Nop { .. } => None,
    }
}

// ─── Dangerous Sinks ──────────────────────────────────────────────────────────

/// Finding type for dangerous sink detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingType {
    CommandInjection,
    BufferOverflow,
    FormatString,
    SqlInjection,
    PathTraversal,
    UseAfterFree,
    IntegerOverflow,
    TaintedCondition,
    Custom(String),
}

impl fmt::Display for FindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandInjection => write!(f, "CommandInjection"),
            Self::BufferOverflow => write!(f, "BufferOverflow"),
            Self::FormatString => write!(f, "FormatString"),
            Self::SqlInjection => write!(f, "SqlInjection"),
            Self::PathTraversal => write!(f, "PathTraversal"),
            Self::UseAfterFree => write!(f, "UseAfterFree"),
            Self::IntegerOverflow => write!(f, "IntegerOverflow"),
            Self::TaintedCondition => write!(f, "TaintedCondition"),
            Self::Custom(s) => write!(f, "Custom({s})"),
        }
    }
}

/// A taint-analysis finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFinding {
    pub finding_type: FindingType,
    /// Address of the dangerous sink.
    pub sink_addr: u64,
    /// Address where the taint was introduced.
    pub source_addr: u64,
    /// Which taint sources contributed.
    pub taint_sources: TaintId,
    /// Propagation path (addresses).
    pub path: Vec<u64>,
    pub description: String,
}

impl TaintFinding {
    pub fn new(
        finding_type: FindingType,
        sink_addr: u64,
        taint_sources: TaintId,
        description: impl Into<String>,
    ) -> Self {
        Self {
            finding_type,
            sink_addr,
            source_addr: 0,
            taint_sources,
            path: Vec::new(),
            description: description.into(),
        }
    }
}

/// Check if a function call hits a dangerous sink.
fn check_dangerous_sink(
    target: &str,
    args: &[TaintExpr],
    state: &TaintState,
    addr: u64,
) -> Option<TaintFinding> {
    let arg0_taint = args
        .first()
        .map(|a| eval_taint(a, state))
        .unwrap_or(taint_bits::NONE);
    let arg1_taint = args
        .get(1)
        .map(|a| eval_taint(a, state))
        .unwrap_or(taint_bits::NONE);
    let arg2_taint = args
        .get(2)
        .map(|a| eval_taint(a, state))
        .unwrap_or(taint_bits::NONE);

    // Command injection: system/execve/ShellExecute with tainted arg0
    match target {
        "system" | "execve" | "execl" | "execvp" | "ShellExecute" | "WinExec" | "CreateProcess" => {
            if taint_bits::is_tainted(arg0_taint) {
                return Some(TaintFinding::new(
                    FindingType::CommandInjection,
                    addr,
                    arg0_taint,
                    format!("Tainted data flows into {target}() command argument"),
                ));
            }
        }
        // Buffer overflow: memcpy/strcpy with tainted length
        "memcpy" | "memmove" | "bcopy" => {
            if taint_bits::is_tainted(arg2_taint) {
                return Some(TaintFinding::new(
                    FindingType::BufferOverflow,
                    addr,
                    arg2_taint,
                    format!("Tainted length in {target}()"),
                ));
            }
        }
        "strcpy" | "strcat" => {
            if taint_bits::is_tainted(arg1_taint) {
                return Some(TaintFinding::new(
                    FindingType::BufferOverflow,
                    addr,
                    arg1_taint,
                    format!("Tainted source in {target}()"),
                ));
            }
        }
        "gets" => {
            // gets(buf) — buf is arg0; there is no arg1
            if taint_bits::is_tainted(arg0_taint) {
                return Some(TaintFinding::new(
                    FindingType::BufferOverflow,
                    addr,
                    arg0_taint,
                    format!("Tainted buffer pointer in {target}()"),
                ));
            }
        }
        // Format string: printf/sprintf/fprintf with tainted format arg
        "printf" | "fprintf" | "sprintf" | "snprintf" | "vprintf" | "vsprintf" => {
            // Correct format-argument index per function signature:
            //   printf(fmt, ...)        -> arg0
            //   fprintf(fp, fmt, ...)   -> arg1
            //   sprintf(buf, fmt, ...)  -> arg1
            //   snprintf(buf, n, fmt, ...)  -> arg2
            //   vprintf(fmt, ap)        -> arg0
            //   vsprintf(buf, fmt, ap)  -> arg1
            let fmt_taint = match target {
                "printf" | "vprintf" => arg0_taint,
                "fprintf" | "sprintf" | "vsprintf" => arg1_taint,
                "snprintf" => arg2_taint,
                _ => arg0_taint,
            };
            if taint_bits::is_tainted(fmt_taint) {
                return Some(TaintFinding::new(
                    FindingType::FormatString,
                    addr,
                    fmt_taint,
                    format!("Tainted format string in {target}()"),
                ));
            }
        }
        // SQL injection: sqlite3_exec / mysql_query with tainted query
        "sqlite3_exec" | "mysql_query" | "PQexec" | "sql_exec" => {
            if taint_bits::is_tainted(arg1_taint) {
                return Some(TaintFinding::new(
                    FindingType::SqlInjection,
                    addr,
                    arg1_taint,
                    format!("Tainted SQL query in {target}()"),
                ));
            }
        }
        // Path traversal: file write with tainted path
        "fopen" | "open" | "CreateFile" | "unlink" | "rename" | "mkdir" => {
            if taint_bits::is_tainted(arg0_taint) {
                return Some(TaintFinding::new(
                    FindingType::PathTraversal,
                    addr,
                    arg0_taint,
                    format!("Tainted file path in {target}()"),
                ));
            }
        }
        _ => {}
    }
    None
}

// ─── TaintReport ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintReport {
    pub findings: Vec<TaintFinding>,
    pub cf_taints: Vec<u64>,
    pub total_instructions: u64,
    pub tainted_registers: Vec<String>,
    pub tainted_addresses: Vec<u64>,
}

impl TaintReport {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_finding(&mut self, f: TaintFinding) {
        self.findings.push(f);
    }
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
    pub fn findings_by_type(&self, t: &FindingType) -> Vec<&TaintFinding> {
        self.findings
            .iter()
            .filter(|f| &f.finding_type == t)
            .collect()
    }
    pub fn high_severity_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| {
                matches!(
                    f.finding_type,
                    FindingType::CommandInjection
                        | FindingType::BufferOverflow
                        | FindingType::FormatString
                )
            })
            .count()
    }
}

// ─── TaintAnalysisPass ────────────────────────────────────────────────────────

/// Runs over a sequence of TaintInstr, propagates taint, and returns a report.
pub struct TaintAnalysisPass;

impl TaintAnalysisPass {
    pub fn analyze(instrs: &[TaintInstr], initial_state: TaintState) -> TaintReport {
        let mut state = initial_state;
        let mut report = TaintReport::new();
        for instr in instrs {
            if let Some(finding) = apply_instr(instr, &mut state) {
                report.add_finding(finding);
            }
        }
        report.total_instructions = state.current_ticks;
        report.cf_taints = state.cf_taint.iter().copied().collect();
        report.tainted_registers = state
            .registers
            .iter()
            .filter(|(_, v)| v.is_tainted())
            .map(|(r, _)| r.clone())
            .collect();
        report.tainted_addresses = state
            .memory
            .iter()
            .filter(|(_, v)| v.is_tainted())
            .map(|(a, _)| *a)
            .collect();
        report
    }
}

// ─── Legacy TaintSource (enum) ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintSource {
    UserInput,
    NetworkSocket { port: u16 },
    FileRead { path: String },
    EnvironmentVar { name: String },
    RegistryRead { key: String },
    CommandLineArg { index: usize },
    ReturnValue { function: String },
    Custom(String),
}

impl fmt::Display for TaintSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserInput => write!(f, "user-input"),
            Self::NetworkSocket { port } => write!(f, "network:{port}"),
            Self::FileRead { path } => write!(f, "file:{path}"),
            Self::EnvironmentVar { name } => write!(f, "env:{name}"),
            Self::RegistryRead { key } => write!(f, "reg:{key}"),
            Self::CommandLineArg { index } => write!(f, "argv[{index}]"),
            Self::ReturnValue { function } => write!(f, "ret:{function}"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

impl TaintSource {
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::UserInput => "user-input",
            Self::NetworkSocket { .. } => "network",
            Self::FileRead { .. } => "file",
            Self::EnvironmentVar { .. } => "environment",
            Self::RegistryRead { .. } => "registry",
            Self::CommandLineArg { .. } => "cmdline",
            Self::ReturnValue { .. } => "return-value",
            Self::Custom(_) => "custom",
        }
    }
    #[must_use]
    pub fn default_risk(&self) -> u8 {
        match self {
            Self::UserInput => 90,
            Self::NetworkSocket { .. } => 95,
            Self::FileRead { .. } => 70,
            Self::EnvironmentVar { .. } => 60,
            Self::RegistryRead { .. } => 55,
            Self::CommandLineArg { .. } => 75,
            Self::ReturnValue { .. } => 50,
            Self::Custom(_) => 40,
        }
    }
    /// Convert to TaintId bitmask.
    #[must_use]
    pub fn to_taint_id(&self) -> TaintId {
        match self {
            Self::UserInput => taint_bits::USER_INPUT,
            Self::NetworkSocket { .. } => taint_bits::NETWORK,
            Self::FileRead { .. } => taint_bits::FILE,
            Self::EnvironmentVar { .. } => taint_bits::ENVIRONMENT,
            Self::CommandLineArg { .. } => taint_bits::COMMAND_LINE,
            Self::RegistryRead { .. } => taint_bits::REGISTRY,
            Self::ReturnValue { .. } => taint_bits::CUSTOM_BASE,
            Self::Custom(_) => taint_bits::CUSTOM_BASE,
        }
    }
}

// ─── TaintLocation ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintLocation {
    Register(String),
    Memory(u64),
    Variable(String),
    ReturnValue,
    Argument(usize),
    HeapObject { ptr: u64, offset: u64 },
}

impl fmt::Display for TaintLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "reg:{r}"),
            Self::Memory(a) => write!(f, "mem:{a:#x}"),
            Self::Variable(v) => write!(f, "var:{v}"),
            Self::ReturnValue => write!(f, "retval"),
            Self::Argument(i) => write!(f, "arg[{i}]"),
            Self::HeapObject { ptr, offset } => write!(f, "heap:{ptr:#x}+{offset}"),
        }
    }
}

impl TaintLocation {
    #[must_use]
    pub fn is_register(&self) -> bool {
        matches!(self, Self::Register(_))
    }
    #[must_use]
    pub fn is_memory(&self) -> bool {
        matches!(self, Self::Memory(_))
    }
    #[must_use]
    pub fn is_variable(&self) -> bool {
        matches!(self, Self::Variable(_))
    }
}

// ─── PropagationOp ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropagationOp {
    Assign,
    ArithAdd,
    ArithSub,
    ArithMul,
    BitwiseOr,
    BitwiseAnd,
    Shift,
    Load,
    Store,
    Call,
    Return,
    PhiNode,
}

impl PropagationOp {
    #[must_use]
    pub fn is_transitive(&self) -> bool {
        matches!(
            self,
            Self::Assign
                | Self::ArithAdd
                | Self::ArithSub
                | Self::ArithMul
                | Self::BitwiseOr
                | Self::Shift
                | Self::Load
                | Self::Store
                | Self::Call
                | Self::Return
                | Self::PhiNode
        )
    }
    #[must_use]
    pub fn may_sanitize(&self) -> bool {
        matches!(self, Self::BitwiseAnd)
    }
}

// ─── PropagationStep ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationStep {
    pub from: TaintLocation,
    pub to: TaintLocation,
    pub operation: PropagationOp,
    pub instruction_address: u64,
}

impl fmt::Display for PropagationStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} --[{:?}]--> {} @ {:#x}",
            self.from, self.operation, self.to, self.instruction_address
        )
    }
}

// ─── Legacy TaintedValue ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyTaintedValue {
    pub id: u64,
    pub sources: HashSet<TaintSource>,
    pub propagation_path: Vec<PropagationStep>,
    pub current_location: TaintLocation,
    pub sanitized: bool,
}

impl LegacyTaintedValue {
    pub fn new(id: u64, source: TaintSource, location: TaintLocation) -> Self {
        let mut sources = HashSet::new();
        sources.insert(source);
        Self {
            id,
            sources,
            propagation_path: vec![],
            current_location: location,
            sanitized: false,
        }
    }
    pub fn merge_sources(&mut self, other: &LegacyTaintedValue) {
        self.sources.extend(other.sources.iter().cloned());
    }
    pub fn propagate(&mut self, step: PropagationStep) {
        self.propagation_path.push(step);
    }
    pub fn sanitize(&mut self) {
        self.sanitized = true;
    }
    #[must_use]
    pub fn is_tainted(&self) -> bool {
        !self.sanitized
    }
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
    #[must_use]
    pub fn propagation_depth(&self) -> usize {
        self.propagation_path.len()
    }
}

// ─── TaintAnalyzer ────────────────────────────────────────────────────────────

pub struct TaintAnalyzer {
    pub next_id: u64,
    pub tracked_values: HashMap<u64, LegacyTaintedValue>,
    pub location_map: HashMap<TaintLocation, u64>,
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintLocation>,
    pub sanitizers: HashSet<TaintLocation>,
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        Self {
            next_id: 0,
            tracked_values: HashMap::new(),
            location_map: HashMap::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: HashSet::new(),
        }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn mark_source(&mut self, source: TaintSource, location: TaintLocation) -> u64 {
        let id = self.alloc_id();
        let v = LegacyTaintedValue::new(id, source.clone(), location.clone());
        self.tracked_values.insert(id, v);
        self.location_map.insert(location, id);
        self.sources.push(source);
        id
    }

    pub fn get_at_location(&self, loc: &TaintLocation) -> Option<&LegacyTaintedValue> {
        let id = self.location_map.get(loc)?;
        self.tracked_values.get(id)
    }

    pub fn propagate(
        &mut self,
        from: TaintLocation,
        to: TaintLocation,
        op: PropagationOp,
        instr_addr: u64,
    ) {
        let from_id = self.location_map.get(&from).copied();
        if let Some(fid) = from_id {
            if self.sanitizers.contains(&from) {
                return;
            }
            let new_id = self.alloc_id();
            let step = PropagationStep {
                from: from.clone(),
                to: to.clone(),
                operation: op,
                instruction_address: instr_addr,
            };
            let mut new_val = self.tracked_values[&fid].clone();
            new_val.id = new_id;
            new_val.current_location = to.clone();
            new_val.propagation_path.push(step);
            self.tracked_values.insert(new_id, new_val);
            self.location_map.insert(to, new_id);
        }
    }

    pub fn sanitize_location(&mut self, loc: &TaintLocation) {
        if let Some(&id) = self.location_map.get(loc) && let Some(v) = self.tracked_values.get_mut(&id) {
            v.sanitize();
        }
        self.sanitizers.insert(loc.clone());
    }

    pub fn is_tainted_at(&self, loc: &TaintLocation) -> bool {
        if self.sanitizers.contains(loc) {
            return false;
        }
        self.location_map.contains_key(loc)
    }

    pub fn find_paths_to_sink(&self, sink: &TaintLocation) -> Vec<Vec<PropagationStep>> {
        if let Some(v) = self.get_at_location(sink) {
            vec![v.propagation_path.clone()]
        } else {
            vec![]
        }
    }
}

impl Default for TaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── TaintGraph ───────────────────────────────────────────────────────────────
// Re-export the richer TaintGraph from taint_graph module which has:
//   - ensure_node (no panics on missing nodes)
//   - source/sink marking
//   - BFS path enumeration and shortest-path
//   - depth tracking
pub use taint_graph::TaintGraph;

// ─── TaintPolicy ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPolicy {
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<String>,
    pub sanitizers: Vec<String>,
    pub track_control_flow: bool,
    pub inter_procedural: bool,
}

impl TaintPolicy {
    pub fn new() -> Self {
        Self {
            sources: vec![
                TaintSource::UserInput,
                TaintSource::NetworkSocket { port: 0 },
            ],
            sinks: vec![
                "system".into(),
                "execve".into(),
                "printf".into(),
                "memcpy".into(),
            ],
            sanitizers: vec![
                "sanitize".into(),
                "escape_string".into(),
                "validate_input".into(),
            ],
            track_control_flow: true,
            inter_procedural: false,
        }
    }
    pub fn add_source(&mut self, src: TaintSource) {
        self.sources.push(src);
    }
    pub fn add_sink(&mut self, sink: impl Into<String>) {
        self.sinks.push(sink.into());
    }
    pub fn add_sanitizer(&mut self, san: impl Into<String>) {
        self.sanitizers.push(san.into());
    }
    pub fn is_sink(&self, name: &str) -> bool {
        self.sinks.iter().any(|s| s == name)
    }
    pub fn is_sanitizer(&self, name: &str) -> bool {
        self.sanitizers.iter().any(|s| s == name)
    }
}

impl Default for TaintPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CallSummary ─────────────────────────────────────────────────────────────

/// Summary of a function's taint behavior for inter-procedural analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSummary {
    pub func_addr: u64,
    pub func_name: Option<String>,
    /// Which argument positions propagate taint to the return value.
    pub arg_to_return: Vec<usize>,
    /// Which argument positions propagate taint to other arguments (via pointer).
    pub arg_to_arg: Vec<(usize, usize)>,
    /// Does this function sanitize any argument?
    pub sanitizes: Vec<usize>,
    /// Is this a known dangerous sink?
    pub is_sink: bool,
    pub sink_type: Option<FindingType>,
}

impl CallSummary {
    pub fn new(func_addr: u64) -> Self {
        Self {
            func_addr,
            func_name: None,
            arg_to_return: Vec::new(),
            arg_to_arg: Vec::new(),
            sanitizes: Vec::new(),
            is_sink: false,
            sink_type: None,
        }
    }
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.func_name = Some(name.into());
        self
    }
    pub fn taint_return_from_args(mut self, args: Vec<usize>) -> Self {
        self.arg_to_return = args;
        self
    }
    pub fn mark_sink(mut self, t: FindingType) -> Self {
        self.is_sink = true;
        self.sink_type = Some(t);
        self
    }
}

// ─── InterProcAnalyzer ────────────────────────────────────────────────────────

pub struct InterProcAnalyzer {
    pub summaries: HashMap<u64, CallSummary>,
    pub call_graph: DiGraph<u64, ()>,
    pub addr_to_node: HashMap<u64, NodeIndex>,
}

impl InterProcAnalyzer {
    pub fn new() -> Self {
        Self {
            summaries: HashMap::new(),
            call_graph: DiGraph::new(),
            addr_to_node: HashMap::new(),
        }
    }

    pub fn add_summary(&mut self, summary: CallSummary) {
        let addr = summary.func_addr;
        let idx = self.call_graph.add_node(addr);
        self.addr_to_node.insert(addr, idx);
        self.summaries.insert(addr, summary);
    }

    pub fn add_call_edge(&mut self, caller: u64, callee: u64) {
        let from = self.ensure_node(caller);
        let to = self.ensure_node(callee);
        self.call_graph.add_edge(from, to, ());
    }

    fn ensure_node(&mut self, addr: u64) -> NodeIndex {
        if let Some(&idx) = self.addr_to_node.get(&addr) {
            return idx;
        }
        let idx = self.call_graph.add_node(addr);
        self.addr_to_node.insert(addr, idx);
        idx
    }

    /// Propagate taint through a call site given arg taints.
    pub fn propagate_through_call(&self, func_addr: u64, arg_taints: &[TaintId]) -> TaintId {
        if let Some(summary) = self.summaries.get(&func_addr) {
            let mut result = taint_bits::NONE;
            for &arg_idx in &summary.arg_to_return {
                if let Some(&t) = arg_taints.get(arg_idx) {
                    result |= t;
                }
            }
            result
        } else {
            // Conservative: union all arg taints
            arg_taints.iter().fold(taint_bits::NONE, |acc, &t| acc | t)
        }
    }

    pub fn is_tainted_path(&self, from: u64, to: u64) -> bool {
        let src = match self.addr_to_node.get(&from) {
            Some(&i) => i,
            None => return false,
        };
        let dst = match self.addr_to_node.get(&to) {
            Some(&i) => i,
            None => return false,
        };
        petgraph::algo::has_path_connecting(&self.call_graph, src, dst, None)
    }
}

impl Default for InterProcAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── TaintEngine (high-level facade) ─────────────────────────────────────────

pub struct TaintEngine {
    pub state: TaintState,
    pub policy: TaintPolicy,
    pub report: TaintReport,
    pub inter_proc: InterProcAnalyzer,
}

impl TaintEngine {
    pub fn new(policy: TaintPolicy) -> Self {
        Self {
            state: TaintState::new(),
            policy,
            report: TaintReport::new(),
            inter_proc: InterProcAnalyzer::new(),
        }
    }

    pub fn mark_tainted(&mut self, addr: u64, size: usize, source_id: TaintId) {
        self.state.mark_tainted(addr, size, source_id);
    }

    pub fn mark_register_tainted(&mut self, reg: &str, source_id: TaintId) {
        self.state.taint_reg(reg, source_id);
    }

    pub fn sanitize_register(&mut self, reg: &str) {
        self.state.sanitize_register(reg);
    }
    pub fn sanitize_memory(&mut self, addr: u64, size: usize) {
        self.state.sanitize_memory(addr, size);
    }

    pub fn run(&mut self, instrs: &[TaintInstr]) {
        for instr in instrs {
            if let Some(finding) = apply_instr(instr, &mut self.state) {
                self.report.add_finding(finding);
            }
        }
        self.report.total_instructions = self.state.current_ticks;
        self.report.cf_taints = self.state.cf_taint.iter().copied().collect();
        self.report.tainted_registers = self
            .state
            .registers
            .iter()
            .filter(|(_, v)| v.is_tainted())
            .map(|(r, _)| r.clone())
            .collect();
        self.report.tainted_addresses = self
            .state
            .memory
            .iter()
            .filter(|(_, v)| v.is_tainted())
            .map(|(a, _)| *a)
            .collect();
    }

    pub fn get_report(&self) -> &TaintReport {
        &self.report
    }
}

// ─── TaintSet ─────────────────────────────────────────────────────────────────

/// A set of taint IDs (bitmask-based).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintSet(pub TaintId);

impl TaintSet {
    pub fn empty() -> Self {
        Self(taint_bits::NONE)
    }
    pub fn all() -> Self {
        Self(taint_bits::ALL)
    }
    pub fn add(&mut self, id: TaintId) {
        self.0 |= id;
    }
    pub fn remove(&mut self, id: TaintId) {
        self.0 &= !id;
    }
    pub fn contains(&self, id: TaintId) -> bool {
        self.0 & id != 0
    }
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
    pub fn union(&self, other: &Self) -> Self {
        Self(self.0 | other.0)
    }
    pub fn intersection(&self, other: &Self) -> Self {
        Self(self.0 & other.0)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn _make_state_with_tainted_reg(reg: &str, source: TaintId) -> TaintState {
        let mut s = TaintState::new();
        s.taint_reg(reg, source);
        s
    }

    #[test]
    fn test_taint_id_bits() {
        assert_eq!(taint_bits::USER_INPUT, 1u64);
        assert_eq!(taint_bits::NETWORK, 2u64);
        assert_eq!(taint_bits::FILE, 4u64);
        assert_eq!(taint_bits::ENVIRONMENT, 8u64);
        assert_eq!(taint_bits::COMMAND_LINE, 16u64);
        assert_eq!(taint_bits::REGISTRY, 32u64);
    }

    #[test]
    fn test_taint_set_operations() {
        let mut ts = TaintSet::empty();
        assert!(ts.is_empty());
        ts.add(taint_bits::USER_INPUT);
        assert!(ts.contains(taint_bits::USER_INPUT));
        assert!(!ts.contains(taint_bits::NETWORK));
        ts.remove(taint_bits::USER_INPUT);
        assert!(ts.is_empty());
    }

    #[test]
    fn test_taint_set_union() {
        let mut a = TaintSet::empty();
        a.add(taint_bits::USER_INPUT);
        let mut b = TaintSet::empty();
        b.add(taint_bits::NETWORK);
        let u = a.union(&b);
        assert!(u.contains(taint_bits::USER_INPUT));
        assert!(u.contains(taint_bits::NETWORK));
    }

    #[test]
    fn test_taint_state_register_taint_propagation() {
        let mut state = TaintState::new();
        state.taint_reg("rax", taint_bits::USER_INPUT);
        assert_eq!(state.reg_taint("rax"), taint_bits::USER_INPUT);
        assert_eq!(state.reg_taint("rbx"), taint_bits::NONE);
    }

    #[test]
    fn test_taint_state_memory_mark_and_sanitize() {
        let mut state = TaintState::new();
        state.mark_tainted(0x1000, 4, taint_bits::NETWORK);
        for i in 0..4u64 {
            assert_eq!(state.mem_taint(0x1000 + i), taint_bits::NETWORK);
        }
        state.sanitize_memory(0x1000, 4);
        for i in 0..4u64 {
            assert_eq!(state.mem_taint(0x1000 + i), taint_bits::NONE);
        }
    }

    #[test]
    fn test_taint_state_stack() {
        let mut state = TaintState::new();
        state.set_stack(-8, TaintedValue::tainted(0x41, taint_bits::FILE));
        assert_eq!(state.stack_taint(-8), taint_bits::FILE);
        assert_eq!(state.stack_taint(-4), taint_bits::NONE);
    }

    #[test]
    fn test_eval_taint_const_is_clean() {
        let state = TaintState::new();
        assert_eq!(eval_taint(&TaintExpr::Const(42), &state), taint_bits::NONE);
    }

    #[test]
    fn test_eval_taint_reg_propagation() {
        let mut state = TaintState::new();
        state.taint_reg("rax", taint_bits::USER_INPUT);
        let expr = TaintExpr::Add(
            Box::new(TaintExpr::Reg("rax".into())),
            Box::new(TaintExpr::Const(1)),
        );
        assert_eq!(eval_taint(&expr, &state), taint_bits::USER_INPUT);
    }

    #[test]
    fn test_eval_taint_load_from_tainted_addr() {
        let mut state = TaintState::new();
        state.taint_reg("rdi", taint_bits::NETWORK);
        let expr = TaintExpr::Load {
            addr: Box::new(TaintExpr::Reg("rdi".into())),
            size: 4,
        };
        let taint = eval_taint(&expr, &state);
        // addr is tainted (rdi), so load result is tainted
        assert!(taint_bits::is_tainted(taint));
    }

    #[test]
    fn test_eval_taint_load_from_tainted_memory() {
        let mut state = TaintState::new();
        state.mark_tainted(0x2000, 4, taint_bits::FILE);
        let expr = TaintExpr::Load {
            addr: Box::new(TaintExpr::Const(0x2000)),
            size: 4,
        };
        let taint = eval_taint(&expr, &state);
        assert!(taint_bits::is_tainted(taint));
    }

    #[test]
    fn test_apply_setreg_propagates_taint() {
        let mut state = TaintState::new();
        state.taint_reg("rax", taint_bits::USER_INPUT);
        let instr = TaintInstr::SetReg {
            reg: "rbx".into(),
            src: TaintExpr::Add(
                Box::new(TaintExpr::Reg("rax".into())),
                Box::new(TaintExpr::Const(0)),
            ),
            addr: 0x1000,
        };
        apply_instr(&instr, &mut state);
        assert_eq!(state.reg_taint("rbx"), taint_bits::USER_INPUT);
    }

    #[test]
    fn test_apply_store_propagates_taint_to_memory() {
        let mut state = TaintState::new();
        state.taint_reg("rax", taint_bits::NETWORK);
        let instr = TaintInstr::Store {
            dest: TaintExpr::Const(0x5000),
            val: TaintExpr::Reg("rax".into()),
            addr: 0x1010,
        };
        apply_instr(&instr, &mut state);
        assert!(taint_bits::is_tainted(state.mem_taint(0x5000)));
    }

    #[test]
    fn test_dangerous_sink_command_injection() {
        let mut state = TaintState::new();
        state.taint_reg("rdi", taint_bits::USER_INPUT);
        let instr = TaintInstr::Call {
            target: "system".into(),
            args: vec![TaintExpr::Reg("rdi".into())],
            addr: 0x4000,
        };
        let finding = apply_instr(&instr, &mut state);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().finding_type, FindingType::CommandInjection);
    }

    #[test]
    fn test_dangerous_sink_format_string() {
        let mut state = TaintState::new();
        state.taint_reg("rdi", taint_bits::NETWORK);
        let instr = TaintInstr::Call {
            target: "printf".into(),
            args: vec![TaintExpr::Reg("rdi".into())],
            addr: 0x5000,
        };
        let finding = apply_instr(&instr, &mut state);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().finding_type, FindingType::FormatString);
    }

    #[test]
    fn test_dangerous_sink_buffer_overflow_memcpy() {
        let mut state = TaintState::new();
        state.taint_reg("rdx", taint_bits::USER_INPUT);
        let instr = TaintInstr::Call {
            target: "memcpy".into(),
            args: vec![
                TaintExpr::Const(0x1000),
                TaintExpr::Const(0x2000),
                TaintExpr::Reg("rdx".into()),
            ],
            addr: 0x6000,
        };
        let finding = apply_instr(&instr, &mut state);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().finding_type, FindingType::BufferOverflow);
    }

    #[test]
    fn test_dangerous_sink_path_traversal() {
        let mut state = TaintState::new();
        state.taint_reg("rdi", taint_bits::COMMAND_LINE);
        let instr = TaintInstr::Call {
            target: "fopen".into(),
            args: vec![TaintExpr::Reg("rdi".into()), TaintExpr::Const(0)],
            addr: 0x7000,
        };
        let finding = apply_instr(&instr, &mut state);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().finding_type, FindingType::PathTraversal);
    }

    #[test]
    fn test_dangerous_sink_sql_injection() {
        let mut state = TaintState::new();
        state.taint_reg("rsi", taint_bits::USER_INPUT);
        let instr = TaintInstr::Call {
            target: "sqlite3_exec".into(),
            args: vec![TaintExpr::Const(0), TaintExpr::Reg("rsi".into())],
            addr: 0x8000,
        };
        let finding = apply_instr(&instr, &mut state);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().finding_type, FindingType::SqlInjection);
    }

    #[test]
    fn test_no_finding_clean_sink() {
        let state = TaintState::new();
        let instr = TaintInstr::Call {
            target: "system".into(),
            args: vec![TaintExpr::Const(0x9000)],
            addr: 0xA000,
        };
        let mut state_mut = state;
        let finding = apply_instr(&instr, &mut state_mut);
        assert!(finding.is_none());
    }

    #[test]
    fn test_taint_analysis_pass_full() {
        let mut initial = TaintState::new();
        initial.taint_reg("rdi", taint_bits::USER_INPUT);
        let instrs = vec![
            TaintInstr::SetReg {
                reg: "rax".into(),
                src: TaintExpr::Reg("rdi".into()),
                addr: 0x100,
            },
            TaintInstr::Call {
                target: "system".into(),
                args: vec![TaintExpr::Reg("rax".into())],
                addr: 0x200,
            },
        ];
        let report = TaintAnalysisPass::analyze(&instrs, initial);
        assert!(report.has_findings());
        assert_eq!(
            report.findings[0].finding_type,
            FindingType::CommandInjection
        );
    }

    #[test]
    fn test_taint_analysis_sanitize_clears_finding() {
        let mut initial = TaintState::new();
        initial.taint_reg("rdi", taint_bits::USER_INPUT);
        // Sanitize before sink
        initial.sanitize_register("rdi");
        let instrs = vec![TaintInstr::Call {
            target: "system".into(),
            args: vec![TaintExpr::Reg("rdi".into())],
            addr: 0x300,
        }];
        let report = TaintAnalysisPass::analyze(&instrs, initial);
        assert!(!report.has_findings());
    }

    #[test]
    fn test_control_flow_taint() {
        let mut state = TaintState::new();
        state.taint_reg("rax", taint_bits::NETWORK);
        let instr = TaintInstr::Branch {
            cond: TaintExpr::Reg("rax".into()),
            addr: 0x400,
        };
        apply_instr(&instr, &mut state);
        assert!(state.cf_taint.contains(&0x400));
    }

    #[test]
    fn test_taint_graph_path_detection() {
        let mut g = TaintGraph::new();
        let src = TaintLocation::Register("rax".into());
        let mid = TaintLocation::Memory(0x1000);
        let sink = TaintLocation::Register("rdi".into());
        g.add_node(crate::taint_graph::TaintNodeData::new(src.clone(), 0));
        g.add_node(crate::taint_graph::TaintNodeData::new(mid.clone(), 0));
        g.add_node(crate::taint_graph::TaintNodeData::new(sink.clone(), 0));
        g.add_edge(&src, &mid, PropagationOp::Store, 0x100, 0);
        g.add_edge(&mid, &sink, PropagationOp::Load, 0x200, 0);
        assert!(g.has_path(&src, &sink));
        assert!(!g.has_path(&sink, &src));
    }

    #[test]
    fn test_taint_analyzer_mark_and_propagate() {
        let mut analyzer = TaintAnalyzer::new();
        let src_loc = TaintLocation::Register("rax".into());
        analyzer.mark_source(TaintSource::UserInput, src_loc.clone());
        assert!(analyzer.is_tainted_at(&src_loc));
        let dst_loc = TaintLocation::Register("rbx".into());
        analyzer.propagate(
            src_loc.clone(),
            dst_loc.clone(),
            PropagationOp::Assign,
            0x100,
        );
        assert!(analyzer.is_tainted_at(&dst_loc));
    }

    #[test]
    fn test_taint_analyzer_sanitize() {
        let mut analyzer = TaintAnalyzer::new();
        let loc = TaintLocation::Register("rax".into());
        analyzer.mark_source(TaintSource::NetworkSocket { port: 80 }, loc.clone());
        assert!(analyzer.is_tainted_at(&loc));
        analyzer.sanitize_location(&loc);
        assert!(!analyzer.is_tainted_at(&loc));
    }

    #[test]
    fn test_inter_proc_propagate_conservative() {
        let ip = InterProcAnalyzer::new();
        // Unknown function: union all arg taints
        let arg_taints = vec![taint_bits::USER_INPUT, taint_bits::NONE, taint_bits::FILE];
        let result = ip.propagate_through_call(0xDEAD, &arg_taints);
        assert!(taint_bits::has_bit(result, taint_bits::USER_INPUT));
        assert!(taint_bits::has_bit(result, taint_bits::FILE));
    }

    #[test]
    fn test_inter_proc_with_summary() {
        let mut ip = InterProcAnalyzer::new();
        let summary = CallSummary::new(0x1000).taint_return_from_args(vec![0]);
        ip.add_summary(summary);
        let arg_taints = vec![taint_bits::USER_INPUT, taint_bits::NONE];
        let result = ip.propagate_through_call(0x1000, &arg_taints);
        assert_eq!(result, taint_bits::USER_INPUT);
    }

    #[test]
    fn test_taint_source_to_id() {
        assert_eq!(TaintSource::UserInput.to_taint_id(), taint_bits::USER_INPUT);
        assert_eq!(
            TaintSource::NetworkSocket { port: 80 }.to_taint_id(),
            taint_bits::NETWORK
        );
        assert_eq!(
            TaintSource::FileRead {
                path: "/etc/passwd".into()
            }
            .to_taint_id(),
            taint_bits::FILE
        );
    }

    #[test]
    fn test_taint_report_findings_by_type() {
        let mut report = TaintReport::new();
        report.add_finding(TaintFinding::new(
            FindingType::CommandInjection,
            0x100,
            taint_bits::USER_INPUT,
            "cmd inj",
        ));
        report.add_finding(TaintFinding::new(
            FindingType::FormatString,
            0x200,
            taint_bits::NETWORK,
            "fmt str",
        ));
        let cmd = report.findings_by_type(&FindingType::CommandInjection);
        assert_eq!(cmd.len(), 1);
        assert_eq!(report.finding_count(), 2);
    }

    #[test]
    fn test_taint_policy_defaults() {
        let p = TaintPolicy::new();
        assert!(p.is_sink("system"));
        assert!(p.is_sanitizer("sanitize"));
        assert!(!p.is_sink("strlen"));
    }

    #[test]
    fn test_tainted_value_union() {
        let a = TaintedValue::tainted(1, taint_bits::USER_INPUT);
        let b = TaintedValue::tainted(2, taint_bits::NETWORK);
        let combined = a.union_taints(&b);
        assert!(taint_bits::has_bit(combined, taint_bits::USER_INPUT));
        assert!(taint_bits::has_bit(combined, taint_bits::NETWORK));
    }

    #[test]
    fn test_tainted_value_is_tainted() {
        let clean = TaintedValue::clean();
        assert!(!clean.is_tainted());
        let dirty = TaintedValue::tainted(42, taint_bits::FILE);
        assert!(dirty.is_tainted());
    }

    #[test]
    fn test_engine_end_to_end() {
        let mut engine = TaintEngine::new(TaintPolicy::new());
        engine.mark_register_tainted("rdi", taint_bits::USER_INPUT);
        let instrs = vec![
            TaintInstr::SetReg {
                reg: "rax".into(),
                src: TaintExpr::Reg("rdi".into()),
                addr: 0x10,
            },
            TaintInstr::Call {
                target: "printf".into(),
                args: vec![TaintExpr::Reg("rax".into())],
                addr: 0x20,
            },
        ];
        engine.run(&instrs);
        assert!(engine.get_report().has_findings());
        assert_eq!(
            engine.get_report().findings[0].finding_type,
            FindingType::FormatString
        );
    }

    #[test]
    fn test_taint_propagation_through_xor() {
        let mut state = TaintState::new();
        state.taint_reg("rax", taint_bits::NETWORK);
        let expr = TaintExpr::Xor(
            Box::new(TaintExpr::Reg("rax".into())),
            Box::new(TaintExpr::Const(0xFF)),
        );
        // XOR with constant: taint propagates (conservative)
        assert_eq!(eval_taint(&expr, &state), taint_bits::NETWORK);
    }

    #[test]
    fn test_taint_propagation_memory_range() {
        let mut state = TaintState::new();
        state.mark_tainted(0x3000, 16, taint_bits::REGISTRY);
        for i in 0..16u64 {
            assert_eq!(
                state.mem_taint(0x3000 + i),
                taint_bits::REGISTRY,
                "byte {i} should be tainted"
            );
        }
        assert_eq!(
            state.mem_taint(0x3010),
            taint_bits::NONE,
            "byte beyond range should be clean"
        );
    }
}
