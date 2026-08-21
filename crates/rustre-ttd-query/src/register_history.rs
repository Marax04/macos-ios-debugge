//! Register value history tracking over the trace.
//!
//! Tracks all register changes through the trace, detects register patterns
//! (repeated sequences, loop counters, pointer chasing), computes a register
//! correlation matrix, and finds when specific values were in registers.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use rustre_ttd::{EventKind, TracePosition, TtdTrace};

// ─── RegisterChange ───────────────────────────────────────────────────────────

/// A single change to a register's value at a trace position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterChange {
    /// Trace position when the change occurred.
    pub position: TracePosition,
    /// Register name (e.g., "rax", "rsp", "r8").
    pub register: String,
    /// Previous value (None if this is the first recorded value).
    pub old_value: Option<u64>,
    /// New value after the change.
    pub new_value: u64,
    /// Thread that performed the change.
    pub thread_id: u32,
    /// Kind of event that caused this change.
    pub cause: ChangeCause,
}

impl RegisterChange {
    /// Returns the delta (new - old) if both values are known.
    #[must_use]
    pub fn delta(&self) -> Option<i64> {
        self.old_value.map(|old| (self.new_value as i64).wrapping_sub(old as i64))
    }

    /// Returns true if the value increased from old to new.
    #[must_use]
    pub fn increased(&self) -> bool {
        self.old_value.is_some_and(|old| self.new_value > old)
    }

    /// Returns true if the value decreased from old to new.
    #[must_use]
    pub fn decreased(&self) -> bool {
        self.old_value.is_some_and(|old| self.new_value < old)
    }
}

impl std::fmt::Display for RegisterChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} := {:#x} (was {:?}) tid={}",
            self.position, self.register, self.new_value, self.old_value, self.thread_id
        )
    }
}

// ─── ChangeCause ──────────────────────────────────────────────────────────────

/// What caused this register change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChangeCause {
    /// Register changed during a function call.
    Call,
    /// Register changed during a function return.
    Return,
    /// Register changed during a syscall entry.
    SyscallEntry,
    /// Register changed during a syscall exit.
    SyscallExit,
    /// Register changed due to an exception.
    Exception,
    /// Register changed at a breakpoint.
    Breakpoint,
    /// Inferred from memory writes (e.g., RSP tracking stack pushes).
    MemoryWrite,
    /// Unknown / generic event.
    Unknown,
}

impl std::fmt::Display for ChangeCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Call => "Call",
            Self::Return => "Return",
            Self::SyscallEntry => "SyscallEntry",
            Self::SyscallExit => "SyscallExit",
            Self::Exception => "Exception",
            Self::Breakpoint => "Breakpoint",
            Self::MemoryWrite => "MemoryWrite",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─── RegisterPattern ──────────────────────────────────────────────────────────

/// A detected behavioral pattern in a register's history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegisterPattern {
    /// Register monotonically increments by a fixed step (loop counter).
    MonotonicIncrement {
        register: String,
        step: i64,
        first_pos: TracePosition,
        last_pos: TracePosition,
        count: u64,
    },
    /// Register monotonically decrements by a fixed step (loop counter / stack growth).
    MonotonicDecrement {
        register: String,
        step: i64,
        first_pos: TracePosition,
        last_pos: TracePosition,
        count: u64,
    },
    /// Register oscillates between two values (toggled boolean, flip-flop).
    Oscillation {
        register: String,
        value_a: u64,
        value_b: u64,
        transitions: u64,
        first_pos: TracePosition,
    },
    /// Register repeatedly takes values that look like pointers (high bits set
    /// and 8-byte aligned), suggesting pointer chasing.
    PointerChasing {
        register: String,
        pointer_values: Vec<u64>,
        first_pos: TracePosition,
        last_pos: TracePosition,
    },
    /// Register takes the same value repeatedly (cache-hit or constant loading).
    RepeatedValue {
        register: String,
        value: u64,
        count: u64,
        positions: Vec<TracePosition>,
    },
    /// Register is set once and never changed (global / base pointer).
    Constant {
        register: String,
        value: u64,
        set_at: TracePosition,
    },
    /// Register follows a Fibonacci-like arithmetic sequence.
    ArithmeticSequence {
        register: String,
        initial: u64,
        common_difference: i64,
        length: u64,
        first_pos: TracePosition,
    },
}

impl std::fmt::Display for RegisterPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MonotonicIncrement { register, step, count, .. } => {
                write!(f, "MonoInc({register}, step={step}, n={count})")
            }
            Self::MonotonicDecrement { register, step, count, .. } => {
                write!(f, "MonoDec({register}, step={step}, n={count})")
            }
            Self::Oscillation { register, value_a, value_b, transitions, .. } => {
                write!(f, "Oscillation({register}: {value_a:#x}<->{value_b:#x}, n={transitions})")
            }
            Self::PointerChasing { register, pointer_values, .. } => {
                write!(f, "PtrChasing({register}, n={})", pointer_values.len())
            }
            Self::RepeatedValue { register, value, count, .. } => {
                write!(f, "Repeated({register}={value:#x}, n={count})")
            }
            Self::Constant { register, value, .. } => {
                write!(f, "Constant({register}={value:#x})")
            }
            Self::ArithmeticSequence { register, initial, common_difference, length, .. } => {
                write!(
                    f,
                    "Arithmetic({register}: start={initial:#x}, d={common_difference}, len={length})"
                )
            }
        }
    }
}

// ─── ValueOrigin ──────────────────────────────────────────────────────────────

/// Describes where a register value came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueOrigin {
    /// Register that received the value.
    pub register: String,
    /// The value.
    pub value: u64,
    /// Trace position when the value was placed in the register.
    pub position: TracePosition,
    /// Thread that set the value.
    pub thread_id: u32,
    /// What caused the change.
    pub cause: ChangeCause,
    /// Optional prior register from which this value may have been propagated.
    pub source_register: Option<String>,
}

impl std::fmt::Display for ValueOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} = {:#x} at {} (tid={}, cause={})",
            self.register, self.value, self.position, self.thread_id, self.cause
        )
    }
}

// ─── CorrelationMatrix ────────────────────────────────────────────────────────

/// Pearson correlation matrix between register value time-series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationMatrix {
    /// Register names (row/column labels).
    pub registers: Vec<String>,
    /// Flat correlation matrix, row-major: `data[i * n + j]` = correlation(i, j).
    pub data: Vec<f64>,
}

impl CorrelationMatrix {
    fn new(registers: Vec<String>) -> Self {
        let n = registers.len();
        Self {
            data: vec![0.0; n * n],
            registers,
        }
    }

    /// Get the correlation between two registers by name.
    #[must_use]
    pub fn get(&self, reg_a: &str, reg_b: &str) -> Option<f64> {
        let i = self.registers.iter().position(|r| r == reg_a)?;
        let j = self.registers.iter().position(|r| r == reg_b)?;
        let n = self.registers.len();
        Some(self.data[i * n + j])
    }

    /// Return the pair of registers with the highest absolute correlation
    /// (excluding self-correlations).
    #[must_use]
    pub fn most_correlated(&self) -> Option<(String, String, f64)> {
        let n = self.registers.len();
        let mut best: Option<(usize, usize, f64)> = None;
        for i in 0..n {
            for j in (i + 1)..n {
                let corr = self.data[i * n + j].abs();
                if best.as_ref().is_none_or(|(_, _, c)| corr > *c) {
                    best = Some((i, j, self.data[i * n + j]));
                }
            }
        }
        best.map(|(i, j, c)| (self.registers[i].clone(), self.registers[j].clone(), c))
    }
}

impl std::fmt::Display for CorrelationMatrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.registers.len();
        writeln!(f, "CorrelationMatrix ({n}x{n}):")?;
        for i in 0..n {
            write!(f, "  {}:", self.registers[i])?;
            for j in 0..n {
                write!(f, " {:+.2}", self.data[i * n + j])?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

// ─── RegisterHistory ──────────────────────────────────────────────────────────

/// Complete history of all register changes through a trace.
///
/// Extracted by scanning TTD trace events and synthesizing register changes
/// from call/return/syscall/exception events.
pub struct RegisterHistory {
    /// All changes, sorted by position.
    pub changes: Vec<RegisterChange>,
    /// Index: register name -> list of change indices.
    by_register: HashMap<String, Vec<usize>>,
    /// Current (most recently seen) value per register, per thread.
    current_values: HashMap<(String, u32), u64>,
}

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("register {0} not found in history")]
    RegisterNotFound(String),
    #[error("empty history")]
    Empty,
    #[error("insufficient samples for correlation")]
    InsufficientSamples,
}

impl RegisterHistory {
    /// Build a register history by scanning the trace.
    ///
    /// Register changes are synthesized from event types:
    /// - `Call { from, to }` → simulate RIP := to, and RSP decrement.
    /// - `Return { from, to }` → simulate RIP := to, RSP increment.
    /// - `SyscallEnter { nr, args }` → simulate RAX := nr, RDI/RSI/etc. from args.
    /// - `SyscallExit { nr, ret }` → simulate RAX := ret.
    /// - `Exception { addr, code }` → simulate RIP := addr.
    /// - `Breakpoint { addr }` → simulate RIP := addr.
    pub fn build(trace: &TtdTrace) -> Self {
        let mut changes: Vec<RegisterChange> = Vec::new();
        let mut current_values: HashMap<(String, u32), u64> = HashMap::new();
        let arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

        let push_change = |changes: &mut Vec<RegisterChange>,
                                current: &mut HashMap<(String, u32), u64>,
                                pos: TracePosition,
                                tid: u32,
                                reg: &str,
                                new_val: u64,
                                cause: ChangeCause| {
            let key = (reg.to_string(), tid);
            let old_value = current.get(&key).copied();
            if old_value != Some(new_val) {
                changes.push(RegisterChange {
                    position: pos,
                    register: reg.to_string(),
                    old_value,
                    new_value: new_val,
                    thread_id: tid,
                    cause,
                });
                current.insert(key, new_val);
            }
        };

        let all_events = trace.all_events();
        for ev in &all_events {
            let pos = ev.position;
            let tid = ev.thread_id;

            match &ev.kind {
                EventKind::Call { from: _, to } => {
                    push_change(
                        &mut changes,
                        &mut current_values,
                        pos,
                        tid,
                        "rip",
                        *to,
                        ChangeCause::Call,
                    );
                    // Simulate RSP decrement (8 bytes for return address).
                    let rsp_key = ("rsp".to_string(), tid);
                    let old_rsp = current_values.get(&rsp_key).copied().unwrap_or(0);
                    let new_rsp = old_rsp.wrapping_sub(8);
                    push_change(
                        &mut changes,
                        &mut current_values,
                        pos,
                        tid,
                        "rsp",
                        new_rsp,
                        ChangeCause::Call,
                    );
                }
                EventKind::Return { from: _, to } => {
                    push_change(
                        &mut changes,
                        &mut current_values,
                        pos,
                        tid,
                        "rip",
                        *to,
                        ChangeCause::Return,
                    );
                    let rsp_key = ("rsp".to_string(), tid);
                    let old_rsp = current_values.get(&rsp_key).copied().unwrap_or(0);
                    let new_rsp = old_rsp.wrapping_add(8);
                    push_change(
                        &mut changes,
                        &mut current_values,
                        pos,
                        tid,
                        "rsp",
                        new_rsp,
                        ChangeCause::Return,
                    );
                }
                EventKind::SyscallEnter { nr, args } => {
                    push_change(
                        &mut changes,
                        &mut current_values,
                        pos,
                        tid,
                        "rax",
                        u64::from(*nr),
                        ChangeCause::SyscallEntry,
                    );
                    for (i, &arg) in args.iter().enumerate() {
                        if i < arg_regs.len() {
                            push_change(
                                &mut changes,
                                &mut current_values,
                                pos,
                                tid,
                                arg_regs[i],
                                arg,
                                ChangeCause::SyscallEntry,
                            );
                        }
                    }
                }
                EventKind::SyscallExit { nr: _, ret } => {
                    push_change(
                        &mut changes,
                        &mut current_values,
                        pos,
                        tid,
                        "rax",
                        *ret,
                        ChangeCause::SyscallExit,
                    );
                }
                EventKind::Exception { addr, code: _ } => {
                    push_change(
                        &mut changes,
                        &mut current_values,
                        pos,
                        tid,
                        "rip",
                        *addr,
                        ChangeCause::Exception,
                    );
                }
                EventKind::Breakpoint { addr } => {
                    push_change(
                        &mut changes,
                        &mut current_values,
                        pos,
                        tid,
                        "rip",
                        *addr,
                        ChangeCause::Breakpoint,
                    );
                }
                EventKind::MemWrite { addr, data } => {
                    // Simulate: if we detect something that looks like a stack push
                    // (write at RSP - 8), record it as a possible RBP save etc.
                    let rsp_key = ("rsp".to_string(), tid);
                    if let Some(&rsp) = current_values.get(&rsp_key)
                        && *addr == rsp && data.len() == 8 {
                            let mut buf = [0u8; 8];
                            buf.copy_from_slice(&data[..8]);
                            let val = u64::from_le_bytes(buf);
                            push_change(
                                &mut changes,
                                &mut current_values,
                                pos,
                                tid,
                                "stack_top",
                                val,
                                ChangeCause::MemoryWrite,
                            );
                        }
                }
                EventKind::MemRead { .. }
                | EventKind::ThreadCreate { .. }
                | EventKind::ThreadExit { .. } => {}
            }
        }

        changes.sort_by_key(|c| c.position);

        let mut by_register: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, ch) in changes.iter().enumerate() {
            by_register.entry(ch.register.clone()).or_default().push(idx);
        }

        Self {
            changes,
            by_register,
            current_values,
        }
    }

    /// Final value of `register` on `thread_id` at the end of the recorded
    /// history, or `None` if it was never written on that thread.
    ///
    /// Uses the live `current_values` snapshot built during construction so
    /// it does not require a linear scan of [`Self::changes`].
    #[must_use]
    pub fn final_value(&self, register: &str, thread_id: u32) -> Option<u64> {
        self.current_values
            .get(&(register.to_string(), thread_id))
            .copied()
    }

    /// Iterate over the final `(register, thread_id) -> value` map.
    pub fn iter_final_values(&self) -> impl Iterator<Item = (&str, u32, u64)> + '_ {
        self.current_values
            .iter()
            .map(|((name, tid), v)| (name.as_str(), *tid, *v))
    }

    /// Return all changes for a specific register.
    #[must_use]
    pub fn changes_for(&self, register: &str) -> Vec<&RegisterChange> {
        match self.by_register.get(register) {
            None => Vec::new(),
            Some(indices) => indices.iter().map(|&i| &self.changes[i]).collect(),
        }
    }

    /// Return all changes in a trace position range.
    #[must_use]
    pub fn changes_in_range(
        &self,
        start: TracePosition,
        end: TracePosition,
    ) -> Vec<&RegisterChange> {
        self.changes
            .iter()
            .filter(|c| c.position >= start && c.position <= end)
            .collect()
    }

    /// Find all trace positions where `register` held `value`.
    #[must_use]
    pub fn find_value(
        &self,
        register: &str,
        value: u64,
    ) -> Vec<TracePosition> {
        match self.by_register.get(register) {
            None => Vec::new(),
            Some(indices) => indices
                .iter()
                .filter_map(|&i| {
                    let ch = &self.changes[i];
                    if ch.new_value == value {
                        Some(ch.position)
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }

    /// Return the value of `register` at (or just before) `position`.
    #[must_use]
    pub fn value_at(&self, register: &str, position: TracePosition) -> Option<u64> {
        let indices = self.by_register.get(register)?;
        // Find the last change <= position.
        
        indices
            .iter()
            .filter_map(|&i| {
                let ch = &self.changes[i];
                if ch.position <= position {
                    Some(ch.new_value)
                } else {
                    None
                }
            })
            .next_back()
    }

    /// Return all known register names in the history.
    #[must_use]
    pub fn registers(&self) -> Vec<&str> {
        self.by_register.keys().map(std::string::String::as_str).collect()
    }

    // ─── Pattern detection ────────────────────────────────────────────────────

    /// Detect all register patterns in the history.
    #[must_use]
    pub fn detect_all_patterns(&self) -> Vec<RegisterPattern> {
        let mut patterns = Vec::new();
        for reg in self.registers() {
            let changes = self.changes_for(reg);
            if changes.is_empty() {
                continue;
            }
            let values: Vec<u64> = changes.iter().map(|c| c.new_value).collect();
            let positions: Vec<TracePosition> = changes.iter().map(|c| c.position).collect();

            if let Some(p) = detect_constant_pattern(reg, &values, &positions) {
                patterns.push(p);
            } else if let Some(p) = detect_monotonic_increment(reg, &values, &positions) {
                patterns.push(p);
            } else if let Some(p) = detect_monotonic_decrement(reg, &values, &positions) {
                patterns.push(p);
            } else if let Some(p) = detect_oscillation(reg, &values, &positions) {
                patterns.push(p);
            } else if let Some(p) = detect_pointer_chasing(reg, &values, &positions) {
                patterns.push(p);
            } else if let Some(p) = detect_repeated_value(reg, &values, &positions) {
                patterns.push(p);
            }
            if let Some(p) = detect_arithmetic_sequence(reg, &values, &positions) {
                patterns.push(p);
            }
        }
        patterns
    }

    // ─── Correlation matrix ───────────────────────────────────────────────────

    /// Compute Pearson correlation matrix between all register value series.
    ///
    /// To compare registers that change at different positions, we sample both
    /// at the positions of the union of their changes (forward-filling).
    pub fn compute_correlation_matrix(&self) -> Result<CorrelationMatrix, HistoryError> {
        let regs: Vec<String> = {
            let mut r: Vec<String> = self.by_register.keys().cloned().collect();
            r.sort();
            r
        };

        if regs.is_empty() {
            return Err(HistoryError::Empty);
        }

        // Collect all unique positions across all registers.
        let all_positions: Vec<TracePosition> = {
            let mut pos_set: HashSet<TracePosition> = HashSet::new();
            for ch in &self.changes {
                pos_set.insert(ch.position);
            }
            let mut v: Vec<TracePosition> = pos_set.into_iter().collect();
            v.sort();
            v
        };

        if all_positions.len() < 2 {
            return Err(HistoryError::InsufficientSamples);
        }

        // Sample each register's value at every position (forward-fill).
        let reg_series: Vec<Vec<f64>> = regs
            .iter()
            .map(|reg| {
                let mut current_val: f64 = 0.0;
                let mut series = Vec::with_capacity(all_positions.len());
                let mut change_iter = self.changes_for(reg).into_iter().peekable();
                for &pos in &all_positions {
                    while let Some(ch) = change_iter.peek() {
                        if ch.position <= pos {
                            current_val = ch.new_value as f64;
                            change_iter.next();
                        } else {
                            break;
                        }
                    }
                    series.push(current_val);
                }
                series
            })
            .collect();

        // Compute pairwise Pearson correlation.
        let n_regs = regs.len();
        let mut matrix = CorrelationMatrix::new(regs);

        for i in 0..n_regs {
            for j in 0..n_regs {
                let corr = pearson_correlation(&reg_series[i], &reg_series[j]);
                matrix.data[i * n_regs + j] = corr;
            }
        }

        Ok(matrix)
    }

    // ─── Value origin tracing ─────────────────────────────────────────────────

    /// Find the origin of a specific value: search for when and how it first
    /// appeared in any register.
    #[must_use]
    pub fn trace_value_origins(&self, value: u64) -> Vec<ValueOrigin> {
        let mut origins = Vec::new();

        // Group all first occurrences per (register, thread).
        let mut seen: HashMap<(String, u32), TracePosition> = HashMap::new();

        for ch in &self.changes {
            if ch.new_value != value {
                continue;
            }
            let key = (ch.register.clone(), ch.thread_id);
            if seen.contains_key(&key) {
                continue;
            }
            seen.insert(key.clone(), ch.position);

            // Look backwards for a prior change to any register with the same value.
            let source_register = self
                .changes
                .iter()
                .rev()
                .find(|c| c.position < ch.position && c.new_value == value && c.register != ch.register)
                .map(|c| c.register.clone());

            origins.push(ValueOrigin {
                register: ch.register.clone(),
                value,
                position: ch.position,
                thread_id: ch.thread_id,
                cause: ch.cause,
                source_register,
            });
        }

        origins.sort_by_key(|o| o.position);
        origins
    }

    /// Build a timeline of (position, value) pairs for a specific register.
    #[must_use]
    pub fn register_timeline(&self, register: &str) -> Vec<(TracePosition, u64)> {
        self.changes_for(register)
            .into_iter()
            .map(|c| (c.position, c.new_value))
            .collect()
    }

    /// Compute per-register change frequency (changes per 1000 ticks).
    #[must_use]
    pub fn change_frequency(&self) -> HashMap<String, f64> {
        if self.changes.is_empty() {
            return HashMap::new();
        }
        let span = self
            .changes
            .last()
            .map_or(0, |c| c.position.sequence)
            .max(1);

        self.by_register
            .iter()
            .map(|(reg, indices)| {
                let rate = indices.len() as f64 / span as f64 * 1000.0;
                (reg.clone(), rate)
            })
            .collect()
    }

    /// Find registers that held values in a given range at any point.
    #[must_use]
    pub fn registers_with_value_in_range(
        &self,
        min_val: u64,
        max_val: u64,
    ) -> Vec<(String, u64, TracePosition)> {
        self.changes
            .iter()
            .filter(|c| c.new_value >= min_val && c.new_value <= max_val)
            .map(|c| (c.register.clone(), c.new_value, c.position))
            .collect()
    }

    /// Compute a sliding-window histogram of how often each register changes
    /// in buckets of `bucket_size` ticks.
    #[must_use]
    pub fn change_histogram(&self, register: &str, bucket_size: u64) -> BTreeMap<u64, u64> {
        let mut hist: BTreeMap<u64, u64> = BTreeMap::new();
        for ch in self.changes_for(register) {
            let bucket = ch.position.sequence / bucket_size.max(1);
            *hist.entry(bucket).or_default() += 1;
        }
        hist
    }

    /// Detect N-gram patterns in register value sequences.
    ///
    /// Returns the most common value n-grams (sequences of N consecutive values).
    #[must_use]
    pub fn value_ngrams(
        &self,
        register: &str,
        n: usize,
    ) -> Vec<(Vec<u64>, u64)> {
        let values: Vec<u64> = self
            .changes_for(register)
            .into_iter()
            .map(|c| c.new_value)
            .collect();

        if values.len() < n {
            return Vec::new();
        }

        let mut counts: HashMap<Vec<u64>, u64> = HashMap::new();
        for window in values.windows(n) {
            *counts.entry(window.to_vec()).or_default() += 1;
        }

        let mut result: Vec<(Vec<u64>, u64)> = counts.into_iter().collect();
        result.sort_by_key(|b| std::cmp::Reverse(b.1));
        result
    }
}

impl std::fmt::Debug for RegisterHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterHistory")
            .field("changes", &self.changes.len())
            .field("registers", &self.by_register.len())
            .finish_non_exhaustive()
    }
}

// ─── Pattern detection helpers ────────────────────────────────────────────────

fn detect_constant_pattern(
    reg: &str,
    values: &[u64],
    positions: &[TracePosition],
) -> Option<RegisterPattern> {
    if values.len() < 2 {
        return None;
    }
    let first = values[0];
    if values.iter().all(|&v| v == first) {
        return Some(RegisterPattern::Constant {
            register: reg.to_string(),
            value: first,
            set_at: positions[0],
        });
    }
    None
}

fn detect_monotonic_increment(
    reg: &str,
    values: &[u64],
    positions: &[TracePosition],
) -> Option<RegisterPattern> {
    if values.len() < 3 {
        return None;
    }
    let step = (values[1] as i64).wrapping_sub(values[0] as i64);
    if step <= 0 {
        return None;
    }
    let count = values
        .windows(2)
        .take_while(|w| (w[1] as i64).wrapping_sub(w[0] as i64) == step)
        .count() as u64
        + 1;
    if count >= 3 {
        let last_idx = (count as usize - 1).min(positions.len().saturating_sub(1));
        Some(RegisterPattern::MonotonicIncrement {
            register: reg.to_string(),
            step,
            first_pos: positions[0],
            last_pos: positions[last_idx],
            count,
        })
    } else {
        None
    }
}

fn detect_monotonic_decrement(
    reg: &str,
    values: &[u64],
    positions: &[TracePosition],
) -> Option<RegisterPattern> {
    if values.len() < 3 {
        return None;
    }
    let step = (values[1] as i64).wrapping_sub(values[0] as i64);
    if step >= 0 {
        return None;
    }
    let count = values
        .windows(2)
        .take_while(|w| (w[1] as i64).wrapping_sub(w[0] as i64) == step)
        .count() as u64
        + 1;
    if count >= 3 {
        let last_idx = (count as usize - 1).min(positions.len().saturating_sub(1));
        Some(RegisterPattern::MonotonicDecrement {
            register: reg.to_string(),
            step: -step,
            first_pos: positions[0],
            last_pos: positions[last_idx],
            count,
        })
    } else {
        None
    }
}

fn detect_oscillation(
    reg: &str,
    values: &[u64],
    positions: &[TracePosition],
) -> Option<RegisterPattern> {
    if values.len() < 4 {
        return None;
    }
    let a = values[0];
    let b = values[1];
    if a == b {
        return None;
    }
    let transitions = values
        .windows(2)
        .filter(|w| (w[0] == a && w[1] == b) || (w[0] == b && w[1] == a))
        .count() as u64;
    if transitions >= 3 {
        Some(RegisterPattern::Oscillation {
            register: reg.to_string(),
            value_a: a,
            value_b: b,
            transitions,
            first_pos: positions[0],
        })
    } else {
        None
    }
}

fn detect_pointer_chasing(
    reg: &str,
    values: &[u64],
    positions: &[TracePosition],
) -> Option<RegisterPattern> {
    if values.len() < 3 {
        return None;
    }
    // Heuristic: values look like user-space pointers if they are >= 4096,
    // 8-byte aligned, and change each time (pointer chasing).
    let pointer_values: Vec<u64> = values
        .iter()
        .copied()
        .filter(|&v| v >= 4096 && v % 8 == 0 && v < 0x0000_7fff_ffff_ffff)
        .collect();
    if pointer_values.len() < 3 {
        return None;
    }
    let unique: HashSet<u64> = pointer_values.iter().copied().collect();
    if unique.len() >= 3 {
        let first_pos = positions[0];
        let last_pos = *positions.last().unwrap();
        Some(RegisterPattern::PointerChasing {
            register: reg.to_string(),
            pointer_values,
            first_pos,
            last_pos,
        })
    } else {
        None
    }
}

fn detect_repeated_value(
    reg: &str,
    values: &[u64],
    positions: &[TracePosition],
) -> Option<RegisterPattern> {
    if values.len() < 2 {
        return None;
    }
    let mut freq: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, &v) in values.iter().enumerate() {
        freq.entry(v).or_default().push(i);
    }
    let best = freq
        .iter()
        .max_by_key(|(_, idxs)| idxs.len())?;
    let count = best.1.len() as u64;
    if count >= 3 && count * 2 > values.len() as u64 {
        let idx_positions: Vec<TracePosition> = best.1.iter().map(|&i| positions[i]).collect();
        Some(RegisterPattern::RepeatedValue {
            register: reg.to_string(),
            value: *best.0,
            count,
            positions: idx_positions,
        })
    } else {
        None
    }
}

fn detect_arithmetic_sequence(
    reg: &str,
    values: &[u64],
    positions: &[TracePosition],
) -> Option<RegisterPattern> {
    if values.len() < 4 {
        return None;
    }
    let d = (values[1] as i64).wrapping_sub(values[0] as i64);
    let length = values
        .windows(2)
        .take_while(|w| (w[1] as i64).wrapping_sub(w[0] as i64) == d)
        .count() as u64
        + 1;
    // Clamp length to positions.len() to avoid out-of-bounds if values and
    // positions are somehow different lengths (defensive).
    let _ = length.min(positions.len() as u64); // keep length for the pattern field
    if length >= 4 && !positions.is_empty() {
        Some(RegisterPattern::ArithmeticSequence {
            register: reg.to_string(),
            initial: values[0],
            common_difference: d,
            length,
            first_pos: positions[0],
        })
    } else {
        None
    }
}

// ─── Pearson correlation ──────────────────────────────────────────────────────

fn pearson_correlation(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len().min(ys.len());
    if n < 2 {
        return 0.0;
    }
    let mean_x = xs[..n].iter().sum::<f64>() / n as f64;
    let mean_y = ys[..n].iter().sum::<f64>() / n as f64;

    let mut cov = 0.0f64;
    let mut var_x = 0.0f64;
    let mut var_y = 0.0f64;

    for i in 0..n {
        let dx = xs[i] - mean_x;
        let dy = ys[i] - mean_y;
        cov = dx.mul_add(dy, cov);
        var_x = dx.mul_add(dx, var_x);
        var_y = dy.mul_add(dy, var_y);
    }

    let denom = (var_x * var_y).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (cov / denom).clamp(-1.0, 1.0)
    }
}

// ─── Utility ──────────────────────────────────────────────────────────────────

/// Find all (register, value, position) triples where a specific value was
/// first seen in any register, across the entire trace.
#[must_use]
pub fn first_occurrences_of_value(
    history: &RegisterHistory,
    value: u64,
) -> Vec<(String, TracePosition)> {
    let mut result: Vec<(String, TracePosition)> = Vec::new();
    let mut seen_regs: HashSet<String> = HashSet::new();
    for ch in &history.changes {
        if ch.new_value == value && seen_regs.insert(ch.register.clone()) {
            result.push((ch.register.clone(), ch.position));
        }
    }
    result
}

/// Compute the longest streak of a register holding a value above a threshold.
#[must_use]
pub fn longest_above_threshold(
    history: &RegisterHistory,
    register: &str,
    threshold: u64,
) -> Option<(TracePosition, TracePosition, u64)> {
    let changes = history.changes_for(register);
    if changes.is_empty() {
        return None;
    }

    let mut best_len = 0u64;
    let mut best_start = None;
    let mut best_end = None;
    let mut cur_len = 0u64;
    let mut cur_start: Option<TracePosition> = None;

    for ch in &changes {
        if ch.new_value > threshold {
            cur_len += 1;
            if cur_start.is_none() {
                cur_start = Some(ch.position);
            }
            if cur_len > best_len {
                best_len = cur_len;
                best_start = cur_start;
                best_end = Some(ch.position);
            }
        } else {
            cur_len = 0;
            cur_start = None;
        }
    }

    match (best_start, best_end) {
        (Some(s), Some(e)) => Some((s, e, best_len)),
        _ => None,
    }
}
