//! Conditional breakpoints: a breakpoint that fires only when a user-defined
//! condition expression evaluates to true.
//!
//! Conditions are small boolean expressions over register names, memory reads,
//! and integer literals.  Evaluation is synchronous and allocation-free for
//! simple cases.

use std::collections::HashMap;
use std::fmt;

use crate::{Breakpoint, BreakpointKind};
use rustre_core::address::Address;

// ── ConditionError ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionError {
    EmptyExpression,
    ParseError(String),
    UnknownRegister(String),
    UnknownVariable(String),
    DivisionByZero,
    MemoryReadError { addr: u64 },
    EvalError(String),
}

impl fmt::Display for ConditionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyExpression => write!(f, "condition expression is empty"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
            Self::UnknownRegister(r) => write!(f, "unknown register: {r}"),
            Self::UnknownVariable(v) => write!(f, "unknown variable: {v}"),
            Self::DivisionByZero => write!(f, "division by zero in condition"),
            Self::MemoryReadError { addr } => {
                write!(f, "memory read error at {addr:#018x}")
            }
            Self::EvalError(s) => write!(f, "evaluation error: {s}"),
        }
    }
}

impl std::error::Error for ConditionError {}

// ── ConditionOperator ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionOperator {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    BitAnd,
    BitOr,
}

impl ConditionOperator {
    /// Apply the operator to two 64-bit register-width values.
    ///
    /// Ordering comparisons are **signed**, and that is a correction rather
    /// than a preference. Unsigned ordering made `rax < 0` impossible to
    /// satisfy, so a breakpoint set to catch a negative return value — the
    /// single most common conditional breakpoint there is — never fired, and
    /// nothing said why; while `rax > 0` was TRUE for `rax == -1`, stopping on
    /// exactly the case the user was trying to exclude. It also disagreed with
    /// this crate's other evaluator (`expression_evaluator`, which compares
    /// `lv`/`rv` as `i64`) and with gdb and lldb, which treat a register as a
    /// signed 64-bit quantity. Same expression, two verdicts, depending on
    /// which path evaluated it.
    ///
    /// `Eq`/`Ne` and the bit tests are unaffected: they do not depend on
    /// signedness.
    const fn apply(&self, lhs: u64, rhs: u64) -> bool {
        let (l, r) = (lhs.cast_signed(), rhs.cast_signed());
        match self {
            Self::Eq => lhs == rhs,
            Self::Ne => lhs != rhs,
            Self::Lt => l < r,
            Self::Le => l <= r,
            Self::Gt => l > r,
            Self::Ge => l >= r,
            Self::BitAnd => (lhs & rhs) != 0,
            Self::BitOr => (lhs | rhs) != 0,
        }
    }
}

impl fmt::Display for ConditionOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Eq => "==",
                Self::Ne => "!=",
                Self::Lt => "<",
                Self::Le => "<=",
                Self::Gt => ">",
                Self::Ge => ">=",
                Self::BitAnd => "&",
                Self::BitOr => "|",
            }
        )
    }
}

// ── ConditionOperand ─────────────────────────────────────────────────────────

/// One side of a binary condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionOperand {
    /// A CPU register by name (e.g. `"rax"`, `"eip"`).
    Register(String),
    /// A memory read of `width` bytes at an absolute address.
    Memory { addr: u64, width: u8 },
    /// An integer literal.
    Literal(u64),
    /// A named user variable (supplied by the caller at evaluation time).
    Variable(String),
}

impl fmt::Display for ConditionOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "{r}"),
            Self::Memory { addr, width } => write!(f, "mem{width}[{addr:#x}]"),
            Self::Literal(n) => write!(f, "{n:#x}"),
            Self::Variable(v) => write!(f, "${v}"),
        }
    }
}

// ── BreakpointCondition ───────────────────────────────────────────────────────

/// A single comparison condition: `lhs op rhs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakpointCondition {
    pub lhs: ConditionOperand,
    pub operator: ConditionOperator,
    pub rhs: ConditionOperand,
    /// Human-readable source expression.
    pub expression: String,
}

impl BreakpointCondition {
    #[must_use]
    pub fn new(
        lhs: ConditionOperand,
        operator: ConditionOperator,
        rhs: ConditionOperand,
    ) -> Self {
        let expression = format!("{lhs} {operator} {rhs}");
        Self {
            lhs,
            operator,
            rhs,
            expression,
        }
    }

    /// Build a simple `register == value` condition.
    #[must_use]
    pub fn reg_eq(register: impl Into<String>, value: u64) -> Self {
        let reg = register.into();
        let expr = format!("{reg} == {value:#x}");
        Self {
            lhs: ConditionOperand::Register(reg),
            operator: ConditionOperator::Eq,
            rhs: ConditionOperand::Literal(value),
            expression: expr,
        }
    }

    /// Build a `register != value` condition.
    #[must_use]
    pub fn reg_ne(register: impl Into<String>, value: u64) -> Self {
        let reg = register.into();
        let expr = format!("{reg} != {value:#x}");
        Self {
            lhs: ConditionOperand::Register(reg),
            operator: ConditionOperator::Ne,
            rhs: ConditionOperand::Literal(value),
            expression: expr,
        }
    }
}

impl fmt::Display for BreakpointCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.expression)
    }
}

// ── EvalContext ───────────────────────────────────────────────────────────────

/// Supplies register values, memory reads, and user variables to condition evaluation.
pub trait EvalContext {
    /// Read a named register.  Returns `None` if the register is unknown.
    fn register(&self, name: &str) -> Option<u64>;

    /// Read `width` bytes from `addr` and return them as a little-endian u64.
    fn read_memory(&self, addr: u64, width: u8) -> Option<u64>;

    /// Look up a named user variable.
    fn variable(&self, name: &str) -> Option<u64> {
        let _ = name;
        None
    }
}

/// A simple in-memory [`EvalContext`] backed by `HashMap`s.  Useful for tests.
#[derive(Debug, Default, Clone)]
pub struct MapEvalContext {
    pub registers: HashMap<String, u64>,
    pub variables: HashMap<String, u64>,
    pub memory: HashMap<u64, Vec<u8>>,
}

impl MapEvalContext {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_reg(&mut self, name: impl Into<String>, value: u64) {
        self.registers.insert(name.into(), value);
    }

    pub fn set_var(&mut self, name: impl Into<String>, value: u64) {
        self.variables.insert(name.into(), value);
    }

    /// Write `width` bytes (little-endian) at `addr`.
    pub fn set_mem(&mut self, addr: u64, value: u64, width: u8) {
        let bytes = value.to_le_bytes();
        let entry = self.memory.entry(addr).or_insert_with(|| vec![0u8; 8]);
        entry.resize(8, 0);
        let copy_len = (width as usize).min(8);
        entry[..copy_len].copy_from_slice(&bytes[..copy_len]);
    }
}

impl EvalContext for MapEvalContext {
    fn register(&self, name: &str) -> Option<u64> {
        self.registers.get(name).copied()
    }

    fn read_memory(&self, addr: u64, width: u8) -> Option<u64> {
        let bytes = self.memory.get(&addr)?;
        let width = (width as usize).min(8).min(bytes.len());
        let mut buf = [0u8; 8];
        buf[..width].copy_from_slice(&bytes[..width]);
        Some(u64::from_le_bytes(buf))
    }

    fn variable(&self, name: &str) -> Option<u64> {
        self.variables.get(name).copied()
    }
}

// ── evaluate_condition ────────────────────────────────────────────────────────

fn resolve_operand(
    op: &ConditionOperand,
    ctx: &dyn EvalContext,
) -> Result<u64, ConditionError> {
    match op {
        ConditionOperand::Register(name) => ctx
            .register(name)
            .ok_or_else(|| ConditionError::UnknownRegister(name.clone())),
        ConditionOperand::Memory { addr, width } => ctx
            .read_memory(*addr, *width)
            .ok_or(ConditionError::MemoryReadError { addr: *addr }),
        ConditionOperand::Literal(n) => Ok(*n),
        ConditionOperand::Variable(name) => ctx
            .variable(name)
            .ok_or_else(|| ConditionError::UnknownVariable(name.clone())),
    }
}

/// Evaluate a [`BreakpointCondition`] against the supplied [`EvalContext`].
///
/// Returns `Ok(true)` if the condition is satisfied (breakpoint should fire).
///
/// # Errors
/// Returns a [`ConditionError`] if a register or variable is unknown, or if
/// memory cannot be read at the specified address.
pub fn evaluate_condition(
    condition: &BreakpointCondition,
    ctx: &dyn EvalContext,
) -> Result<bool, ConditionError> {
    let lhs = resolve_operand(&condition.lhs, ctx)?;
    let rhs = resolve_operand(&condition.rhs, ctx)?;
    Ok(condition.operator.apply(lhs, rhs))
}

impl BreakpointCondition {
    /// Parse the textual form a caller actually writes: `lhs <op> rhs`.
    ///
    /// [`crate::Breakpoint::condition`] is a `String` documented as "only stop
    /// when this evaluates to true", and this engine only ever accepted
    /// conditions built programmatically — the two halves of the feature never
    /// met. A caller could set `condition: Some("rax == 0")`, and the debugger
    /// stopped on every hit: a promise made in the type and kept by nobody.
    ///
    /// Accepted operands, deliberately the same four the engine already models:
    /// a register name (`rax`), an integer literal (`10`, `0x1f`), a variable
    /// (`$name`), and a sized memory read (`mem4[0x1000]`, or `[0x1000]` for the
    /// 8-byte default).
    ///
    /// # Errors
    /// [`ConditionError::EmptyExpression`] for a blank string,
    /// [`ConditionError::ParseError`] for anything it cannot read. Refusing is
    /// the point: a condition silently treated as "always true" would stop
    /// everywhere, and one treated as "always false" would tell the user their
    /// code never runs.
    pub fn parse(text: &str) -> Result<Self, ConditionError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(ConditionError::EmptyExpression);
        }
        // Longest operators first, or `<` would swallow the `<=` case.
        const OPS: &[(&str, ConditionOperator)] = &[
            ("==", ConditionOperator::Eq),
            ("!=", ConditionOperator::Ne),
            ("<=", ConditionOperator::Le),
            (">=", ConditionOperator::Ge),
            ("&", ConditionOperator::BitAnd),
            ("|", ConditionOperator::BitOr),
            ("<", ConditionOperator::Lt),
            (">", ConditionOperator::Gt),
        ];
        for (sym, op) in OPS {
            if let Some((l, r)) = text.split_once(sym) {
                let lhs = Self::parse_operand(l)?;
                let rhs = Self::parse_operand(r)?;
                return Ok(Self {
                    lhs,
                    operator: op.clone(),
                    rhs,
                    // The text the user actually wrote, kept verbatim so
                    // `condition_summary` echoes their words rather than a
                    // re-rendering of them.
                    expression: text.to_string(),
                });
            }
        }
        Err(ConditionError::ParseError(format!(
            "no comparison operator in {text:?}"
        )))
    }

    fn parse_operand(text: &str) -> Result<ConditionOperand, ConditionError> {
        let t = text.trim();
        if t.is_empty() {
            return Err(ConditionError::EmptyExpression);
        }
        if let Some(name) = t.strip_prefix('$') {
            return Ok(ConditionOperand::Variable(name.to_string()));
        }
        // `mem4[0x1000]` or plain `[0x1000]`, which reads a full word.
        if let Some(open) = t.find('[') {
            let width: u8 = if open == 0 {
                8
            } else {
                let n: u8 = t[..open]
                    .strip_prefix("mem")
                    .and_then(|w| w.parse().ok())
                    .ok_or_else(|| ConditionError::ParseError(format!("bad memory width in {t:?}")))?;
                // Only the widths a `u64` operand can actually hold.
                //
                // Any `u8` was accepted before, and each odd value failed in
                // its own silent way — on the path that decides whether to
                // STOP:
                //
                // * `mem0[..]` read zero bytes and compared as 0, so
                //   `mem0[0x1000] == 0` was permanently true;
                // * `mem16[..]` was read as sixteen bytes and packed into
                //   eight, discarding the top half, so the comparison quietly
                //   used only the low word;
                // * `mem3[..]` is not a width any reader produces, so the
                //   operand never resolved at all.
                //
                // The fail-open rule does not catch any of them, because
                // PARSING succeeded: the condition WAS applied, just to the
                // wrong value. Refusing sends them down
                // `should_stop_for_condition`'s unparsable path instead, which
                // stops on every hit — noisy and visible, which this crate
                // prefers to silent and wrong.
                if !matches!(n, 1 | 2 | 4 | 8) {
                    return Err(ConditionError::ParseError(format!(
                        "memory width {n} in {t:?} is not one a 64-bit operand can hold; use mem1, mem2, mem4 or mem8"
                    )));
                }
                n
            };
            let inner = t[open + 1..]
                .strip_suffix(']')
                .ok_or_else(|| ConditionError::ParseError(format!("unclosed [ in {t:?}")))?;
            let addr = Self::parse_int(inner.trim())?;
            return Ok(ConditionOperand::Memory { addr, width });
        }
        if let Ok(n) = Self::parse_int(t) {
            return Ok(ConditionOperand::Literal(n));
        }
        // A bare word is a register. Refuse anything that is not one shape or
        // another rather than inventing a register with a punctuation name.
        if t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Ok(ConditionOperand::Register(t.to_ascii_lowercase()));
        }
        Err(ConditionError::ParseError(format!("unreadable operand {t:?}")))
    }

    /// Parse an integer literal, including a NEGATIVE one.
    ///
    /// `-1` and `-0x10` used to be rejected outright, which is worse than it
    /// sounds: an unparsable condition is fail-open by design (see
    /// `should_stop_for_condition`), so `rax == -1` stopped the target on every
    /// single hit. Error-code checks are the most common conditions people
    /// write, and they were the ones that could not be expressed at all.
    ///
    /// The value is stored as its two's-complement `u64`, which is exactly what
    /// the register holds, so the signed comparison in `apply` reads it back
    /// correctly.
    fn parse_int(t: &str) -> Result<u64, ConditionError> {
        let t = t.trim();
        if let Some(rest) = t.strip_prefix('-') {
            let magnitude = Self::parse_int(rest)?;
            // `i64::MIN` has no positive counterpart, so it is spelled as the
            // magnitude 2^63 and negated with wrapping arithmetic; anything
            // larger is not a 64-bit integer and is refused rather than folded.
            if magnitude > 1u64 << 63 {
                return Err(ConditionError::ParseError(format!(
                    "not a 64-bit integer: {t:?}"
                )));
            }
            return Ok(magnitude.wrapping_neg());
        }
        let parsed = t.strip_prefix("0x").map_or_else(
            || t.parse::<u64>().ok(),
            |hex| u64::from_str_radix(hex, 16).ok(),
        );
        parsed.ok_or_else(|| ConditionError::ParseError(format!("not an integer: {t:?}")))
    }
}

/// The memory reads a parsed condition needs, as `(address, width)`.
///
/// [`EvalContext::read_memory`] is synchronous while a debugger's memory reads
/// are not, so the values must be fetched BEFORE evaluation. Asking the
/// condition which addresses it will touch is what makes that possible without
/// reading the whole address space or, worse, silently treating an unavailable
/// read as a comparison against zero.
#[must_use]
pub fn memory_operands(cond: &BreakpointCondition) -> Vec<(u64, u8)> {
    [&cond.lhs, &cond.rhs]
        .into_iter()
        .filter_map(|op| match op {
            ConditionOperand::Memory { addr, width } => Some((*addr, *width)),
            _ => None,
        })
        .collect()
}

/// Should a stop at a breakpoint carrying `condition` be reported to the user?
///
/// The rule for a condition that cannot be READ or EVALUATED is the same one
/// [`ConditionalBreakpointSet::find_firing`] already applies, and it is the
/// important half: **stop anyway**. A breakpoint that silently never fires tells
/// the user their code never reaches that line — a wrong conclusion about their
/// PROGRAM, drawn from a typo in their condition. Stopping is noisy; the user is
/// standing at the breakpoint and can see why.
#[must_use]
pub fn should_stop_for_condition(condition: Option<&str>, ctx: &dyn EvalContext) -> bool {
    let Some(text) = condition else { return true };
    match BreakpointCondition::parse(text) {
        Ok(cond) => evaluate_condition(&cond, ctx).unwrap_or(true),
        Err(_) => true,
    }
}

// ── ConditionalBreakpoint ─────────────────────────────────────────────────────

/// A breakpoint that fires only when all of its conditions are satisfied.
#[derive(Debug, Clone)]
pub struct ConditionalBreakpoint {
    /// Underlying breakpoint configuration.
    pub breakpoint: Breakpoint,
    /// List of conditions (all must be true — AND logic).
    pub conditions: Vec<BreakpointCondition>,
    /// If > 0, the breakpoint fires only every Nth hit after conditions match.
    pub pass_count: u32,
    /// Total number of times this breakpoint was evaluated.
    pub eval_count: u64,
    /// Total number of times this breakpoint fired.
    pub hit_count: u64,
    /// Current pass-count accumulator.
    pass_accumulator: u32,
    /// Whether this breakpoint is enabled.
    pub enabled: bool,
}

impl ConditionalBreakpoint {
    /// Create from an existing [`Breakpoint`].
    #[must_use]
    pub const fn from_breakpoint(bp: Breakpoint) -> Self {
        Self {
            breakpoint: bp,
            conditions: Vec::new(),
            pass_count: 0,
            eval_count: 0,
            hit_count: 0,
            pass_accumulator: 0,
            enabled: true,
        }
    }

    /// Create at `address` with kind [`BreakpointKind::Software`].
    #[must_use]
    pub const fn at(address: Address) -> Self {
        let bp = Breakpoint {
            address,
            kind: BreakpointKind::Software,
            enabled: true,
            hit_count: 0,
            condition: None,
            original_byte: None,
            label: None,
            ignore_count: 0,
            only_thread: None,
            byte_size: None,
        };
        Self::from_breakpoint(bp)
    }

    /// Add a condition.
    pub fn add_condition(&mut self, cond: BreakpointCondition) {
        self.conditions.push(cond);
    }

    /// Replace all conditions.
    pub fn set_conditions(&mut self, conds: Vec<BreakpointCondition>) {
        self.conditions = conds;
    }

    /// Enable or disable this breakpoint.
    pub const fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.breakpoint.enabled = enabled;
    }

    /// Evaluate all conditions against `ctx`.
    ///
    /// Returns `Ok(true)` if the breakpoint should cause a stop.
    ///
    /// # Errors
    /// Propagates any [`ConditionError`] from condition evaluation.
    pub fn should_break(&mut self, ctx: &dyn EvalContext) -> Result<bool, ConditionError> {
        if !self.enabled {
            return Ok(false);
        }

        self.eval_count += 1;

        // Evaluate all conditions (short-circuit on first failure).
        for cond in &self.conditions {
            if !evaluate_condition(cond, ctx)? {
                return Ok(false);
            }
        }

        // Pass-count logic.
        if self.pass_count > 0 {
            self.pass_accumulator += 1;
            if self.pass_accumulator < self.pass_count {
                return Ok(false);
            }
            self.pass_accumulator = 0;
        }

        self.hit_count += 1;
        Ok(true)
    }

    /// Reset hit/eval statistics.
    pub const fn reset_stats(&mut self) {
        self.eval_count = 0;
        self.hit_count = 0;
        self.pass_accumulator = 0;
    }

    /// Summary of the condition expressions for display.
    #[must_use]
    pub fn condition_summary(&self) -> String {
        if self.conditions.is_empty() {
            return "(unconditional)".to_owned();
        }
        self.conditions
            .iter()
            .map(|c| c.expression.as_str())
            .collect::<Vec<_>>()
            .join(" && ")
    }
}

impl fmt::Display for ConditionalBreakpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConditionalBreakpoint @ {} [{}] hits={} evals={}",
            self.breakpoint.address,
            self.condition_summary(),
            self.hit_count,
            self.eval_count,
        )
    }
}

// ── ConditionalBreakpointSet ──────────────────────────────────────────────────

/// Manages a collection of conditional breakpoints.
#[derive(Debug, Default)]
pub struct ConditionalBreakpointSet {
    breakpoints: Vec<ConditionalBreakpoint>,
}

impl ConditionalBreakpointSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a breakpoint, returns its index.
    pub fn add(&mut self, bp: ConditionalBreakpoint) -> usize {
        let idx = self.breakpoints.len();
        self.breakpoints.push(bp);
        idx
    }

    /// Remove by index.
    pub fn remove(&mut self, idx: usize) -> Option<ConditionalBreakpoint> {
        if idx < self.breakpoints.len() {
            Some(self.breakpoints.remove(idx))
        } else {
            None
        }
    }

    /// Iterate over all breakpoints.
    pub fn iter(&self) -> impl Iterator<Item = &ConditionalBreakpoint> {
        self.breakpoints.iter()
    }

    /// Mutable iterator.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut ConditionalBreakpoint> {
        self.breakpoints.iter_mut()
    }

    /// Find breakpoints at `address`, evaluating conditions against `ctx`.
    pub fn find_firing(
        &mut self,
        address: Address,
        ctx: &dyn EvalContext,
    ) -> Vec<usize> {
        let mut firing = Vec::new();
        for (i, bp) in self.breakpoints.iter_mut().enumerate() {
            if bp.breakpoint.address != address {
                continue;
            }
            // `Err` means the condition could not be EVALUATED — an unknown
            // register, a memory read that failed. Comparing against `Ok(true)`
            // folded that into "does not fire", so a condition referring to a
            // misspelled or unavailable register made the breakpoint silently
            // never stop: `should_break` takes care to report the reason and
            // this line threw it away.
            //
            // Silence is the worst answer here. A breakpoint that never fires
            // tells the user their code never reaches that line — a wrong
            // conclusion about their PROGRAM, drawn from a fault in their
            // condition. Firing on an unevaluable condition is noisy, but the
            // user is standing at the breakpoint and can see why.
            match bp.should_break(ctx) {
                Ok(true) => firing.push(i),
                Ok(false) => {}
                Err(_) => {
                    // Fires (see the note above), so it must also be COUNTED as
                    // fired. `should_break` returns early through `?` before it
                    // touches `hit_count`, so without this the breakpoint stops
                    // the program again and again while reporting zero hits —
                    // the statistics would contradict what the user is watching
                    // happen.
                    bp.hit_count += 1;
                    firing.push(i);
                }
            }
        }
        firing
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.breakpoints.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.breakpoints.is_empty()
    }

    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&ConditionalBreakpoint> {
        self.breakpoints.get(idx)
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut ConditionalBreakpoint> {
        self.breakpoints.get_mut(idx)
    }
}

// ── Tracepoint (non-stopping, dprintf-style) ────────────────────────────────
//
// Tier 1, item 3 of the enhancement plan: a breakpoint variant that logs a
// message and auto-continues instead of stopping the target — GDB's
// `dprintf`. Message formatting is lazy: [`Tracepoint::fire`] only builds the
// string after conditions have passed, so a disabled/false tracepoint costs
// one condition check, not a format.

/// One piece of a tracepoint's log message template: either literal text or
/// an operand to resolve and interpolate at fire time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceFormatPart {
    Literal(String),
    Operand(ConditionOperand),
}

/// A log-message template evaluated lazily when a tracepoint fires.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TracepointFormat {
    pub parts: Vec<TraceFormatPart>,
}

impl TracepointFormat {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn literal(mut self, text: impl Into<String>) -> Self {
        self.parts.push(TraceFormatPart::Literal(text.into()));
        self
    }

    #[must_use]
    pub fn operand(mut self, op: ConditionOperand) -> Self {
        self.parts.push(TraceFormatPart::Operand(op));
        self
    }

    /// Resolve every operand against `ctx` and concatenate into the final
    /// message. Only called after a tracepoint's conditions have passed.
    ///
    /// # Errors
    /// Propagates [`ConditionError`] if any operand fails to resolve.
    pub fn render(&self, ctx: &dyn EvalContext) -> Result<String, ConditionError> {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                TraceFormatPart::Literal(s) => out.push_str(s),
                TraceFormatPart::Operand(op) => {
                    let v = resolve_operand(op, ctx)?;
                    out.push_str(&format!("{v:#x}"));
                }
            }
        }
        Ok(out)
    }
}

/// A single logged tracepoint hit: the rendered message plus provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracepointEvent {
    pub address: Address,
    pub message: String,
    pub hit_count: u64,
}

impl fmt::Display for TracepointEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[trace @ {} #{}] {}", self.address, self.hit_count, self.message)
    }
}

/// A non-stopping breakpoint: when hit and its conditions pass, it logs a
/// formatted message and execution auto-continues — the debugger never stops
/// the target for a tracepoint. Zero-cost-when-off: conditions are checked
/// before the message is formatted, and a disabled tracepoint short-circuits
/// before even that.
#[derive(Debug, Clone)]
pub struct Tracepoint {
    pub address: Address,
    /// All conditions must pass (AND logic) for the tracepoint to log. Empty
    /// means "always log".
    pub conditions: Vec<BreakpointCondition>,
    pub format: TracepointFormat,
    pub enabled: bool,
    pub hit_count: u64,
    pub eval_count: u64,
}

impl Tracepoint {
    #[must_use]
    pub fn new(address: Address, format: TracepointFormat) -> Self {
        Self {
            address,
            conditions: Vec::new(),
            format,
            enabled: true,
            hit_count: 0,
            eval_count: 0,
        }
    }

    pub fn add_condition(&mut self, cond: BreakpointCondition) {
        self.conditions.push(cond);
    }

    /// Check conditions and, if they pass, render and return the log message.
    /// Never signals a stop — this is the auto-continue contract. Returns
    /// `Ok(None)` when disabled or a condition fails; the caller should
    /// simply keep the target running either way.
    ///
    /// # Errors
    /// Propagates [`ConditionError`] from condition evaluation or message
    /// rendering.
    pub fn fire(&mut self, ctx: &dyn EvalContext) -> Result<Option<TracepointEvent>, ConditionError> {
        if !self.enabled {
            return Ok(None);
        }
        self.eval_count += 1;
        for cond in &self.conditions {
            if !evaluate_condition(cond, ctx)? {
                return Ok(None);
            }
        }
        self.hit_count += 1;
        let message = self.format.render(ctx)?;
        Ok(Some(TracepointEvent {
            address: self.address,
            message,
            hit_count: self.hit_count,
        }))
    }
}

impl fmt::Display for Tracepoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Tracepoint @ {} conds={} hits={} evals={}",
            self.address,
            self.conditions.len(),
            self.hit_count,
            self.eval_count,
        )
    }
}

/// Manages a collection of tracepoints, keyed implicitly by insertion order
/// (index), mirroring [`ConditionalBreakpointSet`].
#[derive(Debug, Default)]
pub struct TracepointSet {
    tracepoints: Vec<Tracepoint>,
}

impl TracepointSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, tp: Tracepoint) -> usize {
        let idx = self.tracepoints.len();
        self.tracepoints.push(tp);
        idx
    }

    pub fn remove(&mut self, idx: usize) -> Option<Tracepoint> {
        if idx < self.tracepoints.len() {
            Some(self.tracepoints.remove(idx))
        } else {
            None
        }
    }

    /// Fire every tracepoint registered at `address`, returning the log
    /// events for those whose conditions passed. The caller always resumes
    /// execution afterward — tracepoints never request a stop.
    pub fn fire_at(&mut self, address: Address, ctx: &dyn EvalContext) -> Vec<TracepointEvent> {
        let mut events = Vec::new();
        for tp in &mut self.tracepoints {
            if tp.address != address {
                continue;
            }
            if let Ok(Some(ev)) = tp.fire(ctx) {
                events.push(ev);
            }
        }
        events
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.tracepoints.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tracepoints.is_empty()
    }

    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&Tracepoint> {
        self.tracepoints.get(idx)
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut Tracepoint> {
        self.tracepoints.get_mut(idx)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// A memory operand may only claim a width a `u64` can hold.
    ///
    /// `mem<N>[..]` accepted any `u8`, and each odd value failed silently on
    /// the path that decides whether to STOP — the fail-open rule does not
    /// help, because parsing SUCCEEDED and the condition was applied to a
    /// wrong value:
    ///
    /// * `mem0[..]` compared as 0, so `mem0[x] == 0` was permanently true;
    /// * `mem16[..]` was packed into eight bytes, comparing only the low word;
    /// * `mem3[..]` never resolved at all.
    #[test]
    fn a_memory_operand_only_claims_a_width_it_can_hold() {
        for good in ["mem1[0x1000]", "mem2[0x1000]", "mem4[0x1000]", "mem8[0x1000]", "[0x1000]"] {
            let cond = BreakpointCondition::parse(&format!("{good} == 0"))
                .unwrap_or_else(|e| panic!("{good} is a width the evaluator holds: {e:?}"));
            let ops = memory_operands(&cond);
            assert_eq!(ops.len(), 1, "{good} names one memory operand");
            assert!(matches!(ops[0].1, 1 | 2 | 4 | 8), "{good} -> width {}", ops[0].1);
        }

        for bad in ["mem0[0x1000]", "mem3[0x1000]", "mem16[0x1000]", "mem255[0x1000]"] {
            let err = BreakpointCondition::parse(&format!("{bad} == 0"))
                .expect_err("a width the operand cannot hold must be refused, not truncated");
            let msg = format!("{err:?}");
            assert!(
                msg.contains("mem1") || msg.contains("width"),
                "the refusal must say which widths are available: {msg}"
            );
        }
    }

    /// And a refused condition falls through to the fail-open rule, so the
    /// target stops instead of silently comparing the wrong value.
    #[test]
    fn an_unholdable_width_stops_rather_than_comparing_wrongly() {
        let ctx = MapEvalContext::new();
        assert!(
            should_stop_for_condition(Some("mem0[0x1000] == 0"), &ctx),
            "an unparsable condition must stop the target, not evaluate to a convenient answer"
        );
    }

    /// The textual condition a caller writes must actually be honoured.
    ///
    /// `Breakpoint::condition` is a `String` documented as "only stop when this
    /// evaluates to true", and this engine only accepted conditions built
    /// programmatically: the two halves of the feature never met. Setting
    /// `condition: Some("rax == 0")` stopped on every hit — a promise made in the
    /// type and kept by nobody.
    #[test]
    fn a_written_condition_is_parsed_and_decides_whether_to_stop() {
        let mut ctx = MapEvalContext::new();
        ctx.set_reg("rax", 0);
        ctx.set_reg("rcx", 0x20);
        ctx.set_var("limit", 5);
        ctx.set_mem(0x1000, 7, 8);

        // No condition: always stop. Anything else would drop breakpoints.
        assert!(should_stop_for_condition(None, &ctx));

        // Registers, literals (decimal and hex), variables, memory.
        assert!(should_stop_for_condition(Some("rax == 0"), &ctx));
        assert!(!should_stop_for_condition(Some("rax != 0"), &ctx));
        assert!(should_stop_for_condition(Some("rcx >= 0x20"), &ctx));
        assert!(!should_stop_for_condition(Some("rcx < 16"), &ctx));
        assert!(should_stop_for_condition(Some("$limit == 5"), &ctx));
        assert!(should_stop_for_condition(Some("[0x1000] > 5"), &ctx));
        assert!(!should_stop_for_condition(Some("mem8[0x1000] > 100"), &ctx));

        // `<=` must not be read as `<`, or the boundary case flips.
        assert!(should_stop_for_condition(Some("rcx <= 0x20"), &ctx));

        // UNREADABLE or UNEVALUABLE conditions must STOP, never fall silent.
        // A breakpoint that quietly never fires tells the user their code never
        // reaches that line — a wrong conclusion about their program, drawn from
        // a typo in their condition.
        assert!(
            should_stop_for_condition(Some("rax"), &ctx),
            "a condition with no operator was treated as false and the breakpoint vanished"
        );
        assert!(
            should_stop_for_condition(Some("nosuchreg == 1"), &ctx),
            "a condition naming a register the target does not have silenced the breakpoint"
        );
        assert!(should_stop_for_condition(Some("   "), &ctx));
    }
    use super::*;

    fn addr(v: u64) -> Address {
        Address::from(v)
    }

    fn ctx_with_rax(value: u64) -> MapEvalContext {
        let mut ctx = MapEvalContext::new();
        ctx.set_reg("rax", value);
        ctx
    }

    /// A breakpoint that fires must be COUNTED as fired, including when it fires
    /// because its condition could not be evaluated.
    ///
    /// Iteration 305 made an unevaluable condition fire instead of vanishing —
    /// correct, but it left the accounting behind: `should_break` returns early
    /// through `?` before it touches `hit_count`, so the breakpoint stopped the
    /// program again and again while reporting zero hits. The statistics then
    /// contradict what the user is watching happen, which is its own small lie.
    ///
    /// Found by following through on the previous fix rather than by a new
    /// sweep: a change that alters WHEN something fires has to be checked
    /// against everything that counts firings.
    #[test]
    fn a_breakpoint_that_fires_on_an_unevaluable_condition_is_counted() {
        let mut set = ConditionalBreakpointSet::new();
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        bp.add_condition(BreakpointCondition::reg_eq("rxa", 0xDEAD)); // typo, never present
        set.add(bp);

        let ctx = ctx_with_rax(0xDEAD);
        assert_eq!(set.find_firing(addr(0x1000), &ctx).len(), 1);
        assert_eq!(set.find_firing(addr(0x1000), &ctx).len(), 1);

        let bp = set.iter().next().expect("the breakpoint is still registered");
        assert_eq!(
            bp.hit_count, 2,
            "the breakpoint stopped twice but reported {} hits",
            bp.hit_count
        );
    }

    /// A condition that cannot be EVALUATED must not make the breakpoint vanish.
    ///
    /// `should_break` reports an unknown register as `Err(UnknownRegister)` —
    /// careful, correct, and thrown away one level up: `find_firing` compared
    /// `== Ok(true)`, so `Err` folded into "does not fire". A breakpoint whose
    /// condition names a misspelled or unavailable register then never stopped,
    /// silently.
    ///
    /// That silence is the damage. A breakpoint that never fires tells the user
    /// their code never reaches that line — a wrong conclusion about their
    /// PROGRAM, drawn from a fault in their condition. Firing is noisy, but the
    /// user is standing at the breakpoint and can see why.
    #[test]
    fn a_condition_that_cannot_be_evaluated_still_fires() {
        let mut reg = ConditionalBreakpointSet::new();
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        // `rxa` is a typo for `rax`, and no context will ever supply it.
        bp.add_condition(BreakpointCondition::reg_eq("rxa", 0xDEAD));
        reg.add(bp);

        let ctx = ctx_with_rax(0xDEAD);
        let firing = reg.find_firing(addr(0x1000), &ctx);
        assert_eq!(
            firing.len(),
            1,
            "an unevaluable condition made the breakpoint disappear instead of stopping"
        );

        // A condition that CAN be evaluated and is false must still not fire —
        // otherwise this would just make every conditional breakpoint fire.
        let mut reg2 = ConditionalBreakpointSet::new();
        let mut bp2 = ConditionalBreakpoint::at(addr(0x2000));
        bp2.add_condition(BreakpointCondition::reg_eq("rax", 0xDEAD));
        reg2.add(bp2);
        assert!(
            reg2.find_firing(addr(0x2000), &ctx_with_rax(0xBEEF)).is_empty(),
            "a real, false condition must still suppress the breakpoint"
        );
    }

    #[test]
    fn unconditional_bp_always_fires() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        let ctx = MapEvalContext::new();
        assert!(bp.should_break(&ctx).unwrap());
        assert_eq!(bp.hit_count, 1);
    }

    #[test]
    fn reg_eq_condition_fires_when_matched() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        bp.add_condition(BreakpointCondition::reg_eq("rax", 0xDEAD));
        let ctx = ctx_with_rax(0xDEAD);
        assert!(bp.should_break(&ctx).unwrap());
    }

    #[test]
    fn reg_eq_condition_does_not_fire_when_unmatched() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        bp.add_condition(BreakpointCondition::reg_eq("rax", 0xDEAD));
        let ctx = ctx_with_rax(0xBEEF);
        assert!(!bp.should_break(&ctx).unwrap());
        assert_eq!(bp.hit_count, 0);
    }

    #[test]
    fn reg_ne_condition() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        bp.add_condition(BreakpointCondition::reg_ne("rax", 0));
        let ctx = ctx_with_rax(1);
        assert!(bp.should_break(&ctx).unwrap());
    }

    #[test]
    fn multiple_conditions_all_must_pass() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        bp.add_condition(BreakpointCondition::reg_eq("rax", 1));
        bp.add_condition(BreakpointCondition::reg_eq("rbx", 2));
        let mut ctx = MapEvalContext::new();
        ctx.set_reg("rax", 1);
        ctx.set_reg("rbx", 99); // wrong
        assert!(!bp.should_break(&ctx).unwrap());
        ctx.set_reg("rbx", 2);
        assert!(bp.should_break(&ctx).unwrap());
    }

    #[test]
    fn pass_count_fires_every_nth() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        bp.pass_count = 3;
        let ctx = MapEvalContext::new();
        // First two evaluations should not fire.
        assert!(!bp.should_break(&ctx).unwrap());
        assert!(!bp.should_break(&ctx).unwrap());
        // Third should fire.
        assert!(bp.should_break(&ctx).unwrap());
        // Next cycle.
        assert!(!bp.should_break(&ctx).unwrap());
    }

    #[test]
    fn disabled_bp_never_fires() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        bp.set_enabled(false);
        let ctx = MapEvalContext::new();
        assert!(!bp.should_break(&ctx).unwrap());
        assert_eq!(bp.hit_count, 0);
    }

    #[test]
    fn unknown_register_returns_error() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        bp.add_condition(BreakpointCondition::reg_eq("nonexistent", 0));
        let ctx = MapEvalContext::new();
        assert!(matches!(
            bp.should_break(&ctx),
            Err(ConditionError::UnknownRegister(_))
        ));
    }

    #[test]
    fn memory_condition() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        let cond = BreakpointCondition::new(
            ConditionOperand::Memory {
                addr: 0xDEAD_0000,
                width: 4,
            },
            ConditionOperator::Eq,
            ConditionOperand::Literal(0xCAFE_BABE),
        );
        bp.add_condition(cond);
        let mut ctx = MapEvalContext::new();
        ctx.set_mem(0xDEAD_0000, 0xCAFE_BABE, 4);
        assert!(bp.should_break(&ctx).unwrap());
    }

    #[test]
    fn variable_operand() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        let cond = BreakpointCondition::new(
            ConditionOperand::Variable("loop_count".into()),
            ConditionOperator::Ge,
            ConditionOperand::Literal(100),
        );
        bp.add_condition(cond);
        let mut ctx = MapEvalContext::new();
        ctx.set_var("loop_count", 100);
        assert!(bp.should_break(&ctx).unwrap());
        ctx.set_var("loop_count", 99);
        assert!(!bp.should_break(&ctx).unwrap());
    }

    #[test]
    fn reset_stats_clears_counters() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        let ctx = MapEvalContext::new();
        bp.should_break(&ctx).unwrap();
        bp.should_break(&ctx).unwrap();
        bp.reset_stats();
        assert_eq!(bp.eval_count, 0);
        assert_eq!(bp.hit_count, 0);
    }

    #[test]
    fn set_fires_at_matching_address() {
        let mut set = ConditionalBreakpointSet::new();
        let bp = ConditionalBreakpoint::at(addr(0x2000));
        set.add(bp);
        let ctx = MapEvalContext::new();
        let firing = set.find_firing(addr(0x2000), &ctx);
        assert_eq!(firing, vec![0]);
    }

    #[test]
    fn set_does_not_fire_at_wrong_address() {
        let mut set = ConditionalBreakpointSet::new();
        let bp = ConditionalBreakpoint::at(addr(0x2000));
        set.add(bp);
        let ctx = MapEvalContext::new();
        let firing = set.find_firing(addr(0x3000), &ctx);
        assert!(firing.is_empty());
    }

    #[test]
    fn condition_summary_shows_expressions() {
        let mut bp = ConditionalBreakpoint::at(addr(0x1000));
        bp.add_condition(BreakpointCondition::reg_eq("rax", 1));
        bp.add_condition(BreakpointCondition::reg_ne("rbx", 0));
        let summary = bp.condition_summary();
        assert!(summary.contains("rax"));
        assert!(summary.contains("rbx"));
    }

    // ── Tracepoints ──────────────────────────────────────────────────────────

    #[test]
    fn tracepoint_fires_unconditionally_and_renders_message() {
        let fmt = TracepointFormat::new()
            .literal("rax=")
            .operand(ConditionOperand::Register("rax".into()));
        let mut tp = Tracepoint::new(addr(0x1000), fmt);
        let ctx = ctx_with_rax(0xDEAD);
        let ev = tp.fire(&ctx).unwrap().unwrap();
        assert_eq!(ev.message, "rax=0xdead");
        assert_eq!(ev.hit_count, 1);
        assert_eq!(tp.hit_count, 1);
    }

    #[test]
    fn tracepoint_never_signals_stop_it_just_may_return_none() {
        // A tracepoint whose condition fails returns Ok(None) — the caller
        // interprets this as "keep running", never as a stop request.
        let fmt = TracepointFormat::new().literal("hit");
        let mut tp = Tracepoint::new(addr(0x1000), fmt);
        tp.add_condition(BreakpointCondition::reg_eq("rax", 0xDEAD));
        let ctx = ctx_with_rax(0xBEEF);
        assert_eq!(tp.fire(&ctx).unwrap(), None);
        assert_eq!(tp.hit_count, 0);
        assert_eq!(tp.eval_count, 1);
    }

    #[test]
    fn tracepoint_disabled_short_circuits_before_eval() {
        let fmt = TracepointFormat::new().literal("hit");
        let mut tp = Tracepoint::new(addr(0x1000), fmt);
        tp.enabled = false;
        let ctx = MapEvalContext::new();
        assert_eq!(tp.fire(&ctx).unwrap(), None);
        assert_eq!(tp.eval_count, 0);
    }

    #[test]
    fn tracepoint_message_not_rendered_when_condition_fails() {
        // The operand ("bad_reg") would error if resolved — proves the
        // message is only rendered after conditions pass (lazy formatting).
        let fmt = TracepointFormat::new().operand(ConditionOperand::Register("bad_reg".into()));
        let mut tp = Tracepoint::new(addr(0x1000), fmt);
        tp.add_condition(BreakpointCondition::reg_eq("rax", 0xDEAD));
        let ctx = ctx_with_rax(0xBEEF); // condition fails, "bad_reg" never resolved
        assert_eq!(tp.fire(&ctx).unwrap(), None);
    }

    #[test]
    fn tracepoint_set_fires_multiple_at_same_address() {
        let mut set = TracepointSet::new();
        set.add(Tracepoint::new(addr(0x2000), TracepointFormat::new().literal("a")));
        set.add(Tracepoint::new(addr(0x2000), TracepointFormat::new().literal("b")));
        set.add(Tracepoint::new(addr(0x3000), TracepointFormat::new().literal("c")));
        let ctx = MapEvalContext::new();
        let events = set.fire_at(addr(0x2000), &ctx);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].message, "a");
        assert_eq!(events[1].message, "b");
    }

    #[test]
    fn tracepoint_set_no_events_at_wrong_address() {
        let mut set = TracepointSet::new();
        set.add(Tracepoint::new(addr(0x2000), TracepointFormat::new().literal("a")));
        let ctx = MapEvalContext::new();
        assert!(set.fire_at(addr(0x9999), &ctx).is_empty());
    }

    #[test]
    fn tracepoint_set_add_remove_get() {
        let mut set = TracepointSet::new();
        assert!(set.is_empty());
        let idx = set.add(Tracepoint::new(addr(0x1000), TracepointFormat::new()));
        assert_eq!(set.len(), 1);
        assert!(set.get(idx).is_some());
        let removed = set.remove(idx).unwrap();
        assert_eq!(removed.address, addr(0x1000));
        assert!(set.is_empty());
        assert!(set.remove(0).is_none());
    }

    #[test]
    fn tracepoint_event_display_includes_address_and_message() {
        let ev = TracepointEvent { address: addr(0x1234), message: "hello".into(), hit_count: 5 };
        let s = ev.to_string();
        assert!(s.contains("hello"));
        assert!(s.contains('5'));
    }

    /// The most common conditional breakpoint there is: catch a negative
    /// return value. It was impossible to express AND impossible to satisfy.
    ///
    /// Two independent defects met here. The literal `-1` did not parse, and
    /// an unparsable condition is fail-open, so the target stopped on every
    /// hit; and ordering comparisons were unsigned, so `rax < 0` could never
    /// be true while `rax > 0` was true for `rax == -1` — stopping on exactly
    /// the case the user was excluding.
    #[test]
    fn a_negative_value_condition_parses_and_compares_as_signed() {
        let mut ctx = MapEvalContext::new();
        ctx.set_reg("rax", u64::MAX); // -1
        ctx.set_reg("rbx", 5);

        assert!(should_stop_for_condition(Some("rax == -1"), &ctx));
        assert!(should_stop_for_condition(Some("rax < 0"), &ctx));
        assert!(should_stop_for_condition(Some("rax != 0"), &ctx));
        assert!(should_stop_for_condition(Some("rax <= -1"), &ctx));

        // The complement: these must NOT stop. A blanket true would pass the
        // assertions above while meaning nothing, and a fail-open evaluator
        // returns true for anything it cannot handle - so the negatives are
        // what actually pin the behaviour.
        let cond = BreakpointCondition::parse("rax > 0").expect("must parse");
        assert!(
            !evaluate_condition(&cond, &ctx).expect("must evaluate"),
            "-1 is not greater than zero; unsigned ordering said it was"
        );
        let cond = BreakpointCondition::parse("rax == 0").expect("must parse");
        assert!(!evaluate_condition(&cond, &ctx).expect("must evaluate"));

        // Positive values keep behaving.
        let cond = BreakpointCondition::parse("rbx > 0").expect("must parse");
        assert!(evaluate_condition(&cond, &ctx).expect("must evaluate"));
        let cond = BreakpointCondition::parse("rbx < 0").expect("must parse");
        assert!(!evaluate_condition(&cond, &ctx).expect("must evaluate"));
    }

    /// Negative literals in every shape the parser accepts, and a refusal for
    /// what is not a 64-bit integer at all.
    #[test]
    fn negative_literals_parse_in_decimal_and_hex_and_refuse_what_overflows() {
        let mut ctx = MapEvalContext::new();
        ctx.set_reg("rax", (-16i64).cast_unsigned());
        assert!(should_stop_for_condition(Some("rax == -0x10"), &ctx));
        assert!(should_stop_for_condition(Some("rax == -16"), &ctx));

        ctx.set_reg("rcx", 1u64 << 63); // i64::MIN
        let cond = BreakpointCondition::parse("rcx == -9223372036854775808").expect("i64::MIN must parse");
        assert!(evaluate_condition(&cond, &ctx).expect("must evaluate"));

        // One past i64::MIN is not a 64-bit integer: refused, not folded into
        // some other value.
        assert!(BreakpointCondition::parse("rax == -9223372036854775809").is_err());
    }

}
