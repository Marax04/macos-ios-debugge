//! Taint analysis module for `rustre-analysis-vsa`.
//!
//! Taint analysis tracks the flow of potentially attacker-controlled data
//! through a program.  A value is "tainted" if it originated from (or was
//! derived from) a user-controlled source.  Tainted values that reach a
//! sensitive "sink" without being sanitized by a trusted "sanitizer" represent
//! potential security vulnerabilities.
//!
//! This module provides:
//! - [`TaintLabel`] — a bitmask of taint sources.
//! - [`TaintValue`] — the abstract taint domain (`Clean`, `Tainted(label)`,
//!   `Top`).
//! - [`TaintState`] — per-variable taint map.
//! - [`TaintConfig`] — sources, sinks, and sanitizers.
//! - [`TaintAnalyzer`] — a flow-sensitive, intra-procedural forward analysis.
//! - [`TaintReport`] — the set of source→sink violations found.

use std::collections::{HashMap, HashSet};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// TaintLabel
// ─────────────────────────────────────────────────────────────────────────────

/// A bitmask of taint source categories.
///
/// Bit 0 = user input, bit 1 = network, bit 2 = file system, bits 3–7 = custom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TaintLabel(pub u32);

impl TaintLabel {
    /// No taint bits set.
    pub const CLEAN: Self = Self(0);
    /// User-input taint bit.
    pub const USER_INPUT: Self = Self(1 << 0);
    /// Network taint bit.
    pub const NETWORK: Self = Self(1 << 1);
    /// File-system taint bit.
    pub const FILE_SYSTEM: Self = Self(1 << 2);
    /// Environment-variable taint bit.
    pub const ENV_VAR: Self = Self(1 << 3);
    /// All taint bits set.
    pub const ALL: Self = Self(u32::MAX);

    /// Return `true` if this label has no taint bits set.
    #[must_use]
    pub const fn is_clean(self) -> bool {
        self.0 == 0
    }

    /// Return the union (bitwise OR) of two taint labels.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Return the intersection (bitwise AND) of two taint labels.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Return `true` if any bit of `other` is present in this label.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Return `true` if all bits of `other` are present in this label.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Count the number of taint bits set.
    #[must_use]
    pub const fn bit_count(self) -> u32 {
        self.0.count_ones()
    }
}

impl fmt::Display for TaintLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_clean() {
            return f.write_str("CLEAN");
        }
        let mut names = Vec::new();
        if self.contains(Self::USER_INPUT) {
            names.push("USER_INPUT");
        }
        if self.contains(Self::NETWORK) {
            names.push("NETWORK");
        }
        if self.contains(Self::FILE_SYSTEM) {
            names.push("FILE_SYSTEM");
        }
        if self.contains(Self::ENV_VAR) {
            names.push("ENV_VAR");
        }
        let bits = self.0 & !0b1111;
        if bits != 0 {
            names.push("CUSTOM");
        }
        write!(f, "{}", names.join("|"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintValue  — abstract taint domain
// ─────────────────────────────────────────────────────────────────────────────

/// The abstract taint value for one variable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub enum TaintValue {
    /// Definitely untainted.
    #[default]
    Clean,
    /// Tainted with the given source label.
    Tainted(TaintLabel),
    /// Unknown taint status (over-approximation).
    Top,
}

impl TaintValue {
    /// Return `true` if this value is definitely clean.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }

    /// Return `true` if this value may be tainted.
    #[must_use]
    pub const fn is_tainted(&self) -> bool {
        !self.is_clean()
    }

    /// Compute the join (least upper bound) of two taint values.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Clean, x) | (x, Self::Clean) => x.clone(),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Tainted(a), Self::Tainted(b)) => Self::Tainted(a.union(*b)),
        }
    }

    /// Propagate taint through a binary operation: if either operand is tainted,
    /// the result is tainted with the union of source labels.
    #[must_use]
    pub fn propagate_binary(a: &Self, b: &Self) -> Self {
        a.join(b)
    }

    /// Apply a sanitizer: if this value is tainted with any label that the
    /// sanitizer clears, return `Clean`.
    #[must_use]
    pub const fn sanitize(&self, cleared_label: TaintLabel) -> Self {
        match self {
            Self::Clean => Self::Clean,
            Self::Top => Self::Top,
            Self::Tainted(l) => {
                let remaining = TaintLabel(l.0 & !cleared_label.0);
                if remaining.is_clean() {
                    Self::Clean
                } else {
                    Self::Tainted(remaining)
                }
            }
        }
    }

    /// Return the taint label if tainted, `None` otherwise.
    #[must_use]
    pub const fn label(&self) -> Option<TaintLabel> {
        if let Self::Tainted(l) = self {
            Some(*l)
        } else {
            None
        }
    }
}


impl fmt::Display for TaintValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "Clean"),
            Self::Top => write!(f, "Top"),
            Self::Tainted(l) => write!(f, "Tainted({l})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintState  — per-program-point mapping from variables to TaintValue
// ─────────────────────────────────────────────────────────────────────────────

/// Mapping from variable names to their taint values at one program point.
#[derive(Debug, Clone, Default)]
pub struct TaintState {
    /// Variable → taint value.
    pub map: HashMap<String, TaintValue>,
}

impl TaintState {
    /// Create an empty (all-clean) taint state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the taint value of `var`, defaulting to `Clean`.
    #[must_use]
    pub fn get(&self, var: &str) -> TaintValue {
        self.map.get(var).cloned().unwrap_or(TaintValue::Clean)
    }

    /// Set the taint value of `var`.
    pub fn set(&mut self, var: impl Into<String>, value: TaintValue) {
        self.map.insert(var.into(), value);
    }

    /// Mark `var` as tainted with label `label`.
    pub fn mark_tainted(&mut self, var: impl Into<String>, label: TaintLabel) {
        self.map.insert(var.into(), TaintValue::Tainted(label));
    }

    /// Mark `var` as clean.
    pub fn mark_clean(&mut self, var: impl Into<String>) {
        self.map.insert(var.into(), TaintValue::Clean);
    }

    /// Compute the join of two taint states (point-wise LUB).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (var, val) in &other.map {
            let existing = result.map.get(var).cloned().unwrap_or(TaintValue::Clean);
            result.map.insert(var.clone(), existing.join(val));
        }
        result
    }

    /// Return `true` if this state equals `other` (fixed-point check).
    #[must_use]
    pub fn le(&self, other: &Self) -> bool {
        for (var, val) in &self.map {
            let other_val = other.map.get(var).cloned().unwrap_or(TaintValue::Clean);
            if val.join(&other_val) != other_val {
                return false;
            }
        }
        true
    }

    /// Return all tainted variables.
    #[must_use]
    pub fn tainted_vars(&self) -> Vec<&str> {
        // `self.map` is a `HashMap`, so iteration order is unspecified and
        // randomized per-process; sort to make the returned order
        // deterministic and reproducible across runs.
        let mut vars: Vec<&str> = self
            .map
            .iter()
            .filter(|(_, v)| v.is_tainted())
            .map(|(k, _)| k.as_str())
            .collect();
        vars.sort_unstable();
        vars
    }

    /// Return the number of tainted variables.
    #[must_use]
    pub fn taint_count(&self) -> usize {
        self.map.values().filter(|v| v.is_tainted()).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintConfig  — sources, sinks, sanitizers
// ─────────────────────────────────────────────────────────────────────────────

/// A taint source: a variable/call that introduces tainted data.
#[derive(Debug, Clone)]
pub struct TaintSource {
    /// Name of the variable or function that introduces tainted data.
    pub name: String,
    /// The taint label introduced by this source.
    pub label: TaintLabel,
    /// Human-readable description.
    pub description: String,
}

/// A taint sink: a call/use that must not receive tainted data.
#[derive(Debug, Clone)]
pub struct TaintSink {
    /// Name of the function or variable that must not be tainted.
    pub name: String,
    /// The taint labels this sink is sensitive to (0 = any).
    pub sensitive_to: TaintLabel,
    /// Human-readable description.
    pub description: String,
}

/// A sanitizer: a call that removes taint.
#[derive(Debug, Clone)]
pub struct TaintSanitizer {
    /// Name of the function that sanitizes data.
    pub name: String,
    /// Which taint labels this sanitizer clears (0 = all).
    pub clears: TaintLabel,
    /// Human-readable description.
    pub description: String,
}

/// Full taint analysis configuration.
#[derive(Debug, Clone, Default)]
pub struct TaintConfig {
    /// Taint sources.
    pub sources: Vec<TaintSource>,
    /// Taint sinks.
    pub sinks: Vec<TaintSink>,
    /// Sanitizers.
    pub sanitizers: Vec<TaintSanitizer>,
}

impl TaintConfig {
    /// Create an empty configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a source by name and label.
    pub fn add_source(
        &mut self,
        name: impl Into<String>,
        label: TaintLabel,
        desc: impl Into<String>,
    ) {
        self.sources.push(TaintSource {
            name: name.into(),
            label,
            description: desc.into(),
        });
    }

    /// Add a sink by name.
    pub fn add_sink(
        &mut self,
        name: impl Into<String>,
        sensitive_to: TaintLabel,
        desc: impl Into<String>,
    ) {
        self.sinks.push(TaintSink {
            name: name.into(),
            sensitive_to,
            description: desc.into(),
        });
    }

    /// Add a sanitizer by name.
    pub fn add_sanitizer(
        &mut self,
        name: impl Into<String>,
        clears: TaintLabel,
        desc: impl Into<String>,
    ) {
        self.sanitizers.push(TaintSanitizer {
            name: name.into(),
            clears,
            description: desc.into(),
        });
    }

    /// Return `true` if `name` is a taint source.
    #[must_use]
    pub fn is_source(&self, name: &str) -> bool {
        self.sources.iter().any(|s| s.name == name)
    }

    /// Return `true` if `name` is a taint sink.
    #[must_use]
    pub fn is_sink(&self, name: &str) -> bool {
        self.sinks.iter().any(|s| s.name == name)
    }

    /// Return `true` if `name` is a sanitizer.
    #[must_use]
    pub fn is_sanitizer(&self, name: &str) -> bool {
        self.sanitizers.iter().any(|s| s.name == name)
    }

    /// Look up the taint label introduced by source `name`.
    #[must_use]
    pub fn source_label(&self, name: &str) -> Option<TaintLabel> {
        self.sources
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.label)
    }

    /// Look up the taint label cleared by sanitizer `name`.
    /// If `clears` is `CLEAN` (0), this sanitizer clears ALL taint.
    #[must_use]
    pub fn sanitizer_clears(&self, name: &str) -> Option<TaintLabel> {
        self.sanitizers.iter().find(|s| s.name == name).map(|s| {
            if s.clears.is_clean() {
                TaintLabel::ALL
            } else {
                s.clears
            }
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintInstruction  — simplified instruction model for taint transfer
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified instruction model for taint analysis.
#[derive(Debug, Clone)]
pub enum TaintInstruction {
    /// `dst = src`  (copy / move).
    Assign { dst: String, src: String },
    /// `dst = op(src1, src2)`  (binary operation).
    BinOp {
        dst: String,
        src1: String,
        src2: String,
    },
    /// `dst = load(addr_var)`  (memory load).
    Load { dst: String, addr: String },
    /// `store(addr_var, src)`  (memory store).
    Store { addr: String, src: String },
    /// `dst = call(func_name, args)`.
    Call {
        dst: Option<String>,
        func: String,
        args: Vec<String>,
    },
    /// `branch_on(var)` (condition variable).
    Branch { cond: String },
    /// No operation.
    Nop,
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintFlow  — a taint violation (source → sink)
// ─────────────────────────────────────────────────────────────────────────────

/// A detected taint flow violation.
#[derive(Debug, Clone)]
pub struct TaintFlow {
    /// The variable that carries the taint at the sink.
    pub variable: String,
    /// The taint label of the variable.
    pub label: TaintLabel,
    /// The sink name.
    pub sink: String,
    /// The instruction index where the violation was detected.
    pub instr_idx: usize,
}

impl fmt::Display for TaintFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[taint-flow] {} ({}) → sink '{}' at instr {}",
            self.variable, self.label, self.sink, self.instr_idx
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintReport  — summary of all found violations
// ─────────────────────────────────────────────────────────────────────────────

/// The complete report from a taint analysis run.
#[derive(Debug, Clone, Default)]
pub struct TaintReport {
    /// All detected taint flows.
    pub flows: Vec<TaintFlow>,
    /// Final taint state after analysis.
    pub final_state: TaintState,
}

impl TaintReport {
    /// Return `true` if any violations were found.
    #[must_use]
    pub const fn has_violations(&self) -> bool {
        !self.flows.is_empty()
    }

    /// Return the number of violations found.
    #[must_use]
    pub const fn violation_count(&self) -> usize {
        self.flows.len()
    }

    /// Return all violations affecting a given sink.
    #[must_use]
    pub fn flows_to_sink<'a>(&'a self, sink: &str) -> Vec<&'a TaintFlow> {
        self.flows.iter().filter(|f| f.sink == sink).collect()
    }

    /// Return all unique variable names that reach a sink tainted.
    #[must_use]
    pub fn tainted_sink_vars(&self) -> Vec<&str> {
        let mut vars: Vec<&str> = self.flows.iter().map(|f| f.variable.as_str()).collect();
        vars.sort_unstable();
        vars.dedup();
        vars
    }
}

impl fmt::Display for TaintReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "TaintReport: {} violations", self.flows.len())?;
        for flow in &self.flows {
            writeln!(f, "  {flow}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintAnalyzer  — forward dataflow analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Flow-sensitive intra-procedural taint analyzer.
pub struct TaintAnalyzer<'a> {
    config: &'a TaintConfig,
}

impl<'a> TaintAnalyzer<'a> {
    /// Create a new analyzer with the given configuration.
    #[must_use]
    pub const fn new(config: &'a TaintConfig) -> Self {
        Self { config }
    }

    /// Run the analysis over a sequence of instructions.
    #[must_use]
    pub fn analyze(&self, instrs: &[TaintInstruction]) -> TaintReport {
        let mut state = TaintState::new();
        let mut flows = Vec::new();

        for (idx, instr) in instrs.iter().enumerate() {
            self.transfer(instr, &mut state, &mut flows, idx);
        }

        TaintReport {
            flows,
            final_state: state,
        }
    }

    /// Apply the transfer function for one instruction.
    fn transfer(
        &self,
        instr: &TaintInstruction,
        state: &mut TaintState,
        flows: &mut Vec<TaintFlow>,
        idx: usize,
    ) {
        match instr {
            TaintInstruction::Assign { dst, src } => {
                let src_taint = state.get(src);
                state.set(dst, src_taint);
            }
            TaintInstruction::BinOp { dst, src1, src2 } => {
                let t1 = state.get(src1);
                let t2 = state.get(src2);
                state.set(dst, TaintValue::propagate_binary(&t1, &t2));
            }
            TaintInstruction::Load { dst, addr } => {
                // Loads from a tainted pointer propagate taint.
                let addr_taint = state.get(addr);
                state.set(dst, addr_taint);
            }
            TaintInstruction::Store { addr: _, src } => {
                // Taint on stored value doesn't propagate to memory model here
                // (simplified: we don't model memory in taint state).
                let _ = state.get(src);
            }
            TaintInstruction::Call { dst, func, args } => {
                // Check if this is a source
                if let Some(label) = self.config.source_label(func) {
                    if let Some(d) = dst {
                        state.mark_tainted(d, label);
                    }
                    return;
                }

                // Check if this is a sanitizer
                if let Some(cleared) = self.config.sanitizer_clears(func) {
                    for arg in args {
                        let sanitized = state.get(arg).sanitize(cleared);
                        state.set(arg, sanitized);
                    }
                    if let Some(d) = dst {
                        state.mark_clean(d);
                    }
                    return;
                }

                // Check if this is a sink
                if self.config.is_sink(func) {
                    for arg in args {
                        let val = state.get(arg);
                        if let Some(label) = val.label() {
                            flows.push(TaintFlow {
                                variable: arg.clone(),
                                label,
                                sink: func.clone(),
                                instr_idx: idx,
                            });
                        }
                    }
                }

                // Propagate taint from args to result (conservative).
                if let Some(d) = dst {
                    let combined = args
                        .iter()
                        .fold(TaintValue::Clean, |acc, a| acc.join(&state.get(a)));
                    state.set(d, combined);
                }
            }
            TaintInstruction::Branch { cond } => {
                // Branches on tainted conditions are a potential flow,
                // but for simplicity we just track the condition's taint.
                let _ = state.get(cond);
            }
            TaintInstruction::Nop => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantPropagation  — simple lattice-based constant propagation
// ─────────────────────────────────────────────────────────────────────────────

/// An abstract constant value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub enum ConstValue {
    /// No information (initial state).
    #[default]
    Bottom,
    /// A known concrete constant.
    Const(u64),
    /// May be any value.
    Top,
}

impl ConstValue {
    /// Compute the join (LUB) of two abstract values.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => x.clone(),
            (Self::Const(a), Self::Const(b)) if a == b => Self::Const(*a),
            _ => Self::Top,
        }
    }

    /// Return `true` if this is a known constant.
    #[must_use]
    pub const fn is_const(&self) -> bool {
        matches!(self, Self::Const(_))
    }

    /// Return the constant value, if known.
    #[must_use]
    pub const fn const_value(&self) -> Option<u64> {
        if let Self::Const(v) = self {
            Some(*v)
        } else {
            None
        }
    }
}


impl fmt::Display for ConstValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bottom => write!(f, "⊥"),
            Self::Top => write!(f, "⊤"),
            Self::Const(v) => write!(f, "{v:#x}"),
        }
    }
}

/// A simple constant-propagation state (variable → abstract value).
#[derive(Debug, Clone, Default)]
pub struct ConstPropState {
    pub map: HashMap<String, ConstValue>,
}

impl ConstPropState {
    /// Create a new empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the abstract value of `var`.
    #[must_use]
    pub fn get(&self, var: &str) -> ConstValue {
        self.map.get(var).cloned().unwrap_or(ConstValue::Bottom)
    }

    /// Set the abstract value of `var`.
    pub fn set(&mut self, var: impl Into<String>, value: ConstValue) {
        self.map.insert(var.into(), value);
    }

    /// Compute the point-wise join of two states.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (var, val) in &other.map {
            let existing = result.map.get(var).cloned().unwrap_or(ConstValue::Bottom);
            result.map.insert(var.clone(), existing.join(val));
        }
        result
    }

    /// Return all variables with known constant values.
    #[must_use]
    pub fn constants(&self) -> Vec<(&str, u64)> {
        // `self.map` is a `HashMap`; sort by variable name so the result is
        // deterministic across runs instead of depending on hash iteration
        // order.
        let mut consts: Vec<(&str, u64)> = self
            .map
            .iter()
            .filter_map(|(k, v)| v.const_value().map(|c| (k.as_str(), c)))
            .collect();
        consts.sort_unstable_by(|a, b| a.0.cmp(b.0));
        consts
    }

    /// Return the number of constants tracked.
    #[must_use]
    pub fn constant_count(&self) -> usize {
        self.map.values().filter(|v| v.is_const()).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintStatistic  — aggregate statistics over a taint run
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics from a taint analysis run.
#[derive(Debug, Clone)]
pub struct TaintStatistic {
    /// Total instructions analysed.
    pub total_instructions: usize,
    /// Number of taint-introducing (source) instructions.
    pub source_instructions: usize,
    /// Number of sink-checking instructions.
    pub sink_instructions: usize,
    /// Total taint flows detected.
    pub total_flows: usize,
    /// Number of unique taint labels encountered.
    pub unique_labels: usize,
}

impl TaintStatistic {
    /// Compute statistics from a report and its instruction list.
    #[must_use]
    pub fn from_report(
        report: &TaintReport,
        instrs: &[TaintInstruction],
        config: &TaintConfig,
    ) -> Self {
        let source_instructions = instrs
            .iter()
            .filter(|i| {
                if let TaintInstruction::Call { func, .. } = i {
                    config.is_source(func)
                } else {
                    false
                }
            })
            .count();

        let sink_instructions = instrs
            .iter()
            .filter(|i| {
                if let TaintInstruction::Call { func, .. } = i {
                    config.is_sink(func)
                } else {
                    false
                }
            })
            .count();

        let unique_labels: HashSet<u32> = report.flows.iter().map(|f| f.label.0).collect();

        Self {
            total_instructions: instrs.len(),
            source_instructions,
            sink_instructions,
            total_flows: report.flows.len(),
            unique_labels: unique_labels.len(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_config() -> TaintConfig {
        let mut cfg = TaintConfig::new();
        cfg.add_source(
            "read_user_input",
            TaintLabel::USER_INPUT,
            "reads from stdin",
        );
        cfg.add_sink("execute_sql", TaintLabel::USER_INPUT, "SQL execution");
        cfg.add_sanitizer("sanitize_sql", TaintLabel::USER_INPUT, "SQL sanitizer");
        cfg
    }

    #[test]
    fn test_taint_label_clean() {
        assert!(TaintLabel::CLEAN.is_clean());
        assert!(!TaintLabel::USER_INPUT.is_clean());
    }

    #[test]
    fn test_taint_label_union() {
        let a = TaintLabel::USER_INPUT;
        let b = TaintLabel::NETWORK;
        let u = a.union(b);
        assert!(u.contains(TaintLabel::USER_INPUT));
        assert!(u.contains(TaintLabel::NETWORK));
    }

    #[test]
    fn test_taint_label_intersect() {
        let a = TaintLabel::USER_INPUT.union(TaintLabel::NETWORK);
        let b = TaintLabel::USER_INPUT;
        let i = a.intersect(b);
        assert_eq!(i, TaintLabel::USER_INPUT);
    }

    #[test]
    fn test_taint_label_overlaps() {
        assert!(TaintLabel::USER_INPUT.overlaps(TaintLabel::ALL));
        assert!(!TaintLabel::USER_INPUT.overlaps(TaintLabel::NETWORK));
    }

    #[test]
    fn test_taint_label_display() {
        let s = format!("{}", TaintLabel::USER_INPUT);
        assert!(s.contains("USER_INPUT"));
    }

    #[test]
    fn test_taint_label_clean_display() {
        assert_eq!(format!("{}", TaintLabel::CLEAN), "CLEAN");
    }

    #[test]
    fn test_taint_value_join() {
        let a = TaintValue::Clean;
        let b = TaintValue::Tainted(TaintLabel::USER_INPUT);
        let j = a.join(&b);
        assert_eq!(j, TaintValue::Tainted(TaintLabel::USER_INPUT));
    }

    #[test]
    fn test_taint_value_join_two_tainted() {
        let a = TaintValue::Tainted(TaintLabel::USER_INPUT);
        let b = TaintValue::Tainted(TaintLabel::NETWORK);
        let j = a.join(&b);
        assert_eq!(
            j,
            TaintValue::Tainted(TaintLabel::USER_INPUT.union(TaintLabel::NETWORK))
        );
    }

    #[test]
    fn test_taint_value_sanitize() {
        let v = TaintValue::Tainted(TaintLabel::USER_INPUT);
        let s = v.sanitize(TaintLabel::USER_INPUT);
        assert_eq!(s, TaintValue::Clean);
    }

    #[test]
    fn test_taint_value_sanitize_partial() {
        let label = TaintLabel::USER_INPUT.union(TaintLabel::NETWORK);
        let v = TaintValue::Tainted(label);
        let s = v.sanitize(TaintLabel::USER_INPUT);
        // Only USER_INPUT is sanitized; NETWORK remains.
        assert_eq!(s, TaintValue::Tainted(TaintLabel::NETWORK));
    }

    #[test]
    fn test_taint_value_display() {
        assert_eq!(format!("{}", TaintValue::Clean), "Clean");
        assert_eq!(format!("{}", TaintValue::Top), "Top");
    }

    #[test]
    fn test_taint_state_set_get() {
        let mut state = TaintState::new();
        state.mark_tainted("x", TaintLabel::USER_INPUT);
        assert_eq!(state.get("x"), TaintValue::Tainted(TaintLabel::USER_INPUT));
        assert_eq!(state.get("y"), TaintValue::Clean); // default
    }

    #[test]
    fn test_taint_state_tainted_vars() {
        let mut state = TaintState::new();
        state.mark_tainted("x", TaintLabel::USER_INPUT);
        state.mark_clean("y");
        let tv = state.tainted_vars();
        assert!(tv.contains(&"x"));
        assert!(!tv.contains(&"y"));
    }

    #[test]
    fn test_taint_state_join() {
        let mut s1 = TaintState::new();
        s1.mark_tainted("x", TaintLabel::USER_INPUT);
        let mut s2 = TaintState::new();
        s2.mark_tainted("y", TaintLabel::NETWORK);
        let j = s1.join(&s2);
        assert!(j.get("x").is_tainted());
        assert!(j.get("y").is_tainted());
    }

    #[test]
    fn test_taint_state_taint_count() {
        let mut state = TaintState::new();
        state.mark_tainted("a", TaintLabel::USER_INPUT);
        state.mark_tainted("b", TaintLabel::NETWORK);
        assert_eq!(state.taint_count(), 2);
    }

    #[test]
    fn test_taint_config_is_source() {
        let cfg = simple_config();
        assert!(cfg.is_source("read_user_input"));
        assert!(!cfg.is_source("printf"));
    }

    #[test]
    fn test_taint_config_is_sink() {
        let cfg = simple_config();
        assert!(cfg.is_sink("execute_sql"));
        assert!(!cfg.is_sink("read_user_input"));
    }

    #[test]
    fn test_taint_config_is_sanitizer() {
        let cfg = simple_config();
        assert!(cfg.is_sanitizer("sanitize_sql"));
        assert!(!cfg.is_sanitizer("execute_sql"));
    }

    #[test]
    fn test_taint_analyzer_simple_flow() {
        let config = simple_config();
        let analyzer = TaintAnalyzer::new(&config);
        let instrs = vec![
            TaintInstruction::Call {
                dst: Some("x".to_string()),
                func: "read_user_input".to_string(),
                args: vec![],
            },
            TaintInstruction::Call {
                dst: None,
                func: "execute_sql".to_string(),
                args: vec!["x".to_string()],
            },
        ];
        let report = analyzer.analyze(&instrs);
        assert!(report.has_violations());
        assert_eq!(report.violation_count(), 1);
    }

    #[test]
    fn test_taint_analyzer_sanitized_flow() {
        let config = simple_config();
        let analyzer = TaintAnalyzer::new(&config);
        let instrs = vec![
            TaintInstruction::Call {
                dst: Some("x".to_string()),
                func: "read_user_input".to_string(),
                args: vec![],
            },
            TaintInstruction::Call {
                dst: Some("y".to_string()),
                func: "sanitize_sql".to_string(),
                args: vec!["x".to_string()],
            },
            TaintInstruction::Call {
                dst: None,
                func: "execute_sql".to_string(),
                args: vec!["y".to_string()],
            },
        ];
        let report = analyzer.analyze(&instrs);
        // y was sanitized, so no violation
        assert!(!report.has_violations());
    }

    #[test]
    fn test_taint_analyzer_assign_propagates() {
        let config = simple_config();
        let analyzer = TaintAnalyzer::new(&config);
        let instrs = vec![
            TaintInstruction::Call {
                dst: Some("x".to_string()),
                func: "read_user_input".to_string(),
                args: vec![],
            },
            TaintInstruction::Assign {
                dst: "z".to_string(),
                src: "x".to_string(),
            },
            TaintInstruction::Call {
                dst: None,
                func: "execute_sql".to_string(),
                args: vec!["z".to_string()],
            },
        ];
        let report = analyzer.analyze(&instrs);
        assert!(report.has_violations());
    }

    #[test]
    fn test_taint_analyzer_no_flow() {
        let config = simple_config();
        let analyzer = TaintAnalyzer::new(&config);
        let instrs = vec![TaintInstruction::Call {
            dst: None,
            func: "execute_sql".to_string(),
            args: vec!["clean_var".to_string()],
        }];
        let report = analyzer.analyze(&instrs);
        assert!(!report.has_violations());
    }

    #[test]
    fn test_taint_report_flows_to_sink() {
        let config = simple_config();
        let analyzer = TaintAnalyzer::new(&config);
        let instrs = vec![
            TaintInstruction::Call {
                dst: Some("x".to_string()),
                func: "read_user_input".to_string(),
                args: vec![],
            },
            TaintInstruction::Call {
                dst: None,
                func: "execute_sql".to_string(),
                args: vec!["x".to_string()],
            },
        ];
        let report = analyzer.analyze(&instrs);
        assert_eq!(report.flows_to_sink("execute_sql").len(), 1);
        assert!(report.flows_to_sink("nonexistent_sink").is_empty());
    }

    #[test]
    fn test_taint_report_tainted_sink_vars() {
        let config = simple_config();
        let analyzer = TaintAnalyzer::new(&config);
        let instrs = vec![
            TaintInstruction::Call {
                dst: Some("x".to_string()),
                func: "read_user_input".to_string(),
                args: vec![],
            },
            TaintInstruction::Call {
                dst: None,
                func: "execute_sql".to_string(),
                args: vec!["x".to_string()],
            },
        ];
        let report = analyzer.analyze(&instrs);
        assert!(report.tainted_sink_vars().contains(&"x"));
    }

    #[test]
    fn test_const_value_join() {
        let a = ConstValue::Const(42);
        let b = ConstValue::Const(42);
        assert_eq!(a.join(&b), ConstValue::Const(42));
        let c = ConstValue::Const(99);
        assert_eq!(a.join(&c), ConstValue::Top);
    }

    #[test]
    fn test_const_value_display() {
        assert_eq!(format!("{}", ConstValue::Const(255)), "0xff");
        assert_eq!(format!("{}", ConstValue::Bottom), "⊥");
        assert_eq!(format!("{}", ConstValue::Top), "⊤");
    }

    #[test]
    fn test_const_prop_state_constants() {
        let mut state = ConstPropState::new();
        state.set("a", ConstValue::Const(10));
        state.set("b", ConstValue::Top);
        let constants = state.constants();
        assert_eq!(constants.len(), 1);
        assert_eq!(constants[0].1, 10);
    }

    #[test]
    fn test_taint_statistic() {
        let config = simple_config();
        let analyzer = TaintAnalyzer::new(&config);
        let instrs = vec![
            TaintInstruction::Call {
                dst: Some("x".to_string()),
                func: "read_user_input".to_string(),
                args: vec![],
            },
            TaintInstruction::Call {
                dst: None,
                func: "execute_sql".to_string(),
                args: vec!["x".to_string()],
            },
        ];
        let report = analyzer.analyze(&instrs);
        let stats = TaintStatistic::from_report(&report, &instrs, &config);
        assert_eq!(stats.total_instructions, 2);
        assert_eq!(stats.source_instructions, 1);
        assert_eq!(stats.sink_instructions, 1);
        assert_eq!(stats.total_flows, 1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Randomized soundness properties for the taint lattice and transfer function.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod prop_soundness {
    use super::*;

    use crate::test_prng::Xs;

    fn rand_tv(r: &mut Xs) -> TaintValue {
        match r.next() % 4 {
            0 => TaintValue::Clean,
            1 => TaintValue::Top,
            _ => TaintValue::Tainted(TaintLabel((r.next() % 16) as u32)),
        }
    }

    /// le defined via join: a ⊑ b  iff  a ⊔ b = b.
    fn le(a: &TaintValue, b: &TaintValue) -> bool {
        &a.join(b) == b
    }

    #[test]
    fn prop_taint_join_lattice_laws() {
        let mut r = Xs::new(0xCAFE_BABE);
        for _ in 0..8000 {
            let a = rand_tv(&mut r);
            let b = rand_tv(&mut r);
            let c = rand_tv(&mut r);
            // idempotent
            assert_eq!(a.join(&a), a, "join not idempotent: {a}");
            // commutative
            assert_eq!(a.join(&b), b.join(&a), "join not commutative: {a},{b}");
            // associative
            assert_eq!(
                a.join(&b).join(&c),
                a.join(&b.join(&c)),
                "join not associative: {a},{b},{c}"
            );
            // upper bound
            assert!(le(&a, &a.join(&b)), "join not ub of lhs: {a},{b}");
            assert!(le(&b, &a.join(&b)), "join not ub of rhs: {a},{b}");
        }
    }

    /// Note the ordering: Clean(⊥) ⊑ Tainted(l) ⊑ Top(⊤), and
    /// Tainted(a) ⊑ Tainted(b) iff a ⊆ b (bit-subset). Verify le agrees.
    #[test]
    fn prop_taint_le_is_partial_order() {
        let mut r = Xs::new(0x0FF1_CE55);
        for _ in 0..8000 {
            let a = rand_tv(&mut r);
            let b = rand_tv(&mut r);
            // reflexive
            assert!(le(&a, &a));
            // antisymmetric
            if le(&a, &b) && le(&b, &a) {
                assert_eq!(a, b, "le antisymmetry violated: {a},{b}");
            }
            // Clean is bottom, Top is top.
            assert!(le(&TaintValue::Clean, &a), "Clean not bottom vs {a}");
            assert!(le(&a, &TaintValue::Top), "Top not top vs {a}");
        }
    }

    /// propagate_binary must over-approximate the taint of both operands
    /// (a tainted operand cannot yield a clean result).
    #[test]
    fn prop_propagate_binary_over_approximates() {
        let mut r = Xs::new(0xABCD_1234);
        for _ in 0..8000 {
            let a = rand_tv(&mut r);
            let b = rand_tv(&mut r);
            let p = TaintValue::propagate_binary(&a, &b);
            assert!(le(&a, &p), "propagate dropped lhs taint: {a},{b} -> {p}");
            assert!(le(&b, &p), "propagate dropped rhs taint: {a},{b} -> {p}");
            // If either operand may be tainted, the result may be tainted.
            if a.is_tainted() || b.is_tainted() {
                assert!(p.is_tainted(), "propagate lost taint: {a},{b} -> {p}");
            }
        }
    }

    /// sanitize only clears the specified bits; it must never introduce taint,
    /// and must not clear bits outside `cleared`.
    #[test]
    fn prop_sanitize_only_clears_specified() {
        let mut r = Xs::new(0x7777_3333);
        for _ in 0..8000 {
            let v = rand_tv(&mut r);
            let cleared = TaintLabel((r.next() % 16) as u32);
            let s = v.sanitize(cleared);
            // sanitize result ⊑ original (never adds taint)
            assert!(le(&s, &v), "sanitize added taint: {v} -/> {s}");
            if let (Some(before), Some(after)) = (v.label(), s.label()) {
                // no bit outside `cleared` was removed
                let removed = before.0 & !after.0;
                assert_eq!(removed & !cleared.0, 0, "sanitize cleared un-asked bit: {v} clr {} -> {s}", cleared.0);
                // every remaining bit was in `before` and not in `cleared`
                assert_eq!(after.0, before.0 & !cleared.0, "sanitize wrong residue");
            }
        }
    }

    /// TaintState.join is a pointwise upper bound and TaintState.le agrees.
    #[test]
    fn prop_taint_state_join_le() {
        let mut r = Xs::new(0x1212_3434);
        let vars = ["p", "q", "s", "t"];
        for _ in 0..4000 {
            let mk = |r: &mut Xs| {
                let mut st = TaintState::new();
                for v in &vars {
                    if r.next() % 3 != 0 {
                        st.set(*v, rand_tv(r));
                    }
                }
                st
            };
            let a = mk(&mut r);
            let b = mk(&mut r);
            let j = a.join(&b);
            assert!(a.le(&j), "state join not ub of lhs");
            assert!(b.le(&j), "state join not ub of rhs");
            for v in &vars {
                assert!(le(&a.get(v), &j.get(v)));
                assert!(le(&b.get(v), &j.get(v)));
            }
        }
    }

    /// Transfer-function monotonicity: if s1 ⊑ s2 then transfer(s1) ⊑ transfer(s2).
    /// Uses a config with a source, sink and sanitizer to exercise every branch.
    #[test]
    fn prop_transfer_monotone() {
        let mut cfg = TaintConfig::new();
        cfg.add_source("src", TaintLabel::USER_INPUT, "");
        cfg.add_sink("sink", TaintLabel::USER_INPUT, "");
        cfg.add_sanitizer("san", TaintLabel::USER_INPUT, "");
        let analyzer = TaintAnalyzer::new(&cfg);

        let vars = ["a", "b", "c"];
        let mut r = Xs::new(0x5A5A_A5A5);
        for _ in 0..4000 {
            // Build s1 ⊑ s2 by choosing s2 >= s1 per-variable.
            let mut s1 = TaintState::new();
            let mut s2 = TaintState::new();
            for v in &vars {
                let lo = rand_tv(&mut r);
                let hi_extra = rand_tv(&mut r);
                let hi = lo.join(&hi_extra); // guarantees lo ⊑ hi
                s1.set(*v, lo);
                s2.set(*v, hi);
            }
            assert!(s1.le(&s2), "setup: s1 not ⊑ s2");

            // Random instruction.
            let instr = match r.next() % 6 {
                0 => TaintInstruction::Assign { dst: "a".into(), src: "b".into() },
                1 => TaintInstruction::BinOp { dst: "a".into(), src1: "b".into(), src2: "c".into() },
                2 => TaintInstruction::Load { dst: "a".into(), addr: "b".into() },
                3 => TaintInstruction::Call { dst: Some("a".into()), func: "src".into(), args: vec!["b".into()] },
                4 => TaintInstruction::Call { dst: Some("a".into()), func: "san".into(), args: vec!["b".into(), "c".into()] },
                _ => TaintInstruction::Call { dst: Some("a".into()), func: "other".into(), args: vec!["b".into(), "c".into()] },
            };

            let mut o1 = s1.clone();
            let mut o2 = s2.clone();
            let mut f1 = Vec::new();
            let mut f2 = Vec::new();
            analyzer.transfer(&instr, &mut o1, &mut f1, 0);
            analyzer.transfer(&instr, &mut o2, &mut f2, 0);
            assert!(
                o1.le(&o2),
                "transfer non-monotone for {instr:?}: {:?} vs {:?}",
                o1.map,
                o2.map
            );
        }
    }

    #[test]
    fn prop_constvalue_lattice_laws() {
        let mut r = Xs::new(0x0246_8ACE);
        let rand_cv = |r: &mut Xs| match r.next() % 4 {
            0 => ConstValue::Bottom,
            1 => ConstValue::Top,
            _ => ConstValue::Const(r.next() % 8),
        };
        let le = |a: &ConstValue, b: &ConstValue| &a.join(b) == b;
        for _ in 0..8000 {
            let a = rand_cv(&mut r);
            let b = rand_cv(&mut r);
            let c = rand_cv(&mut r);
            assert_eq!(a.join(&a), a);
            assert_eq!(a.join(&b), b.join(&a));
            assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
            assert!(le(&a, &a.join(&b)));
            assert!(le(&b, &a.join(&b)));
            assert!(le(&ConstValue::Bottom, &a));
            assert!(le(&a, &ConstValue::Top));
        }
    }
}
