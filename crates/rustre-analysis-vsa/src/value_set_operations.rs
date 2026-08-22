//! Value Set Operations
//!
//! This module implements abstract interpretation of binary instructions using
//! the `StridedInterval` abstract domain. It provides:
//!
//! * ALU operation lifting (add, sub, mul, div, shifts, bitwise ops).
//! * Memory load / store abstraction over a region-based memory model.
//! * Call side-effect modelling: unknown calls clobber caller-saved registers.
//! * Inter-procedural VSA via function summaries (summary-based approach).
//! * Loop widening with configurable threshold sets to ensure convergence.
//!
//! ## Abstract interpreter design
//!
//! The interpreter works block-by-block in a worklist (chaotic iteration) over
//! the control-flow graph. Each block transforms an incoming `VsaEnv` (a map
//! from variable name to `StridedInterval`) to an outgoing `VsaEnv`. Join is
//! applied at control-flow merge points. Widening is applied when the same
//! block header is visited more than `WIDEN_DELAY` times.
//!
//! Memory is modelled as a map from abstract addresses (region × offset) to
//! strided intervals. A load from an imprecise address joins all possible cells.
//!
//! Inter-procedural summaries record which variables (registers) are
//! *clobbered* and which return a known interval.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::hash::BuildHasher;


use serde::{Deserialize, Serialize};

use crate::strided_interval::{StridedInterval, WideningThresholds};

// ─────────────────────────────────────────────────────────────────────────────
// Abstract environment
// ─────────────────────────────────────────────────────────────────────────────

/// The analysis environment: a map from register / variable name to its
/// abstract value (a `StridedInterval`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsaEnv {
    /// Register / variable bindings.
    pub bindings: HashMap<String, StridedInterval>,
    /// Whether this environment is reachable (false ⟹ dead code).
    pub reachable: bool,
}

impl VsaEnv {
    /// Create an empty, reachable environment.
    #[must_use]
    pub fn new() -> Self {
        Self { bindings: HashMap::new(), reachable: true }
    }

    /// Create a totally unknown (Top) environment for a set of variables.
    #[must_use]
    pub fn top(vars: &[String], bits: u8) -> Self {
        let bindings = vars.iter().map(|v| (v.clone(), StridedInterval::top(bits))).collect();
        Self { bindings, reachable: true }
    }

    /// Create an unreachable environment.
    #[must_use]
    pub fn bottom() -> Self {
        Self { bindings: HashMap::new(), reachable: false }
    }

    /// Look up a variable; returns `Bottom` if not present.
    #[must_use]
    pub fn get(&self, var: &str) -> StridedInterval {
        if !self.reachable {
            return StridedInterval::Bottom;
        }
        self.bindings
            .get(var)
            .copied()
            .unwrap_or(StridedInterval::Bottom)
    }

    /// Bind a variable to a value.
    pub fn set(&mut self, var: impl Into<String>, val: StridedInterval) {
        self.bindings.insert(var.into(), val);
    }

    /// Remove a binding (models a store to an unknown location clobbering a reg).
    pub fn kill(&mut self, var: &str) {
        self.bindings.remove(var);
    }

    /// Lattice join (element-wise).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        if !self.reachable {
            return other.clone();
        }
        if !other.reachable {
            return self.clone();
        }
        let mut result = Self::new();
        let all_keys: HashSet<&String> =
            self.bindings.keys().chain(other.bindings.keys()).collect();
        for key in all_keys {
            let a = self.get(key);
            let b = other.get(key);
            result.set(key.clone(), a.join(&b));
        }
        result
    }

    /// Element-wise widening towards `other`.
    #[must_use]
    pub fn widen(&self, other: &Self, thresholds: &WideningThresholds) -> Self {
        if !self.reachable {
            return other.clone();
        }
        if !other.reachable {
            return self.clone();
        }
        let mut result = Self::new();
        // Iterate the UNION of keys: iterating only `other`'s keys dropped any
        // binding present solely in `self` (a missing binding reads back as
        // Bottom via `get`), so widen(a, b) could be strictly below join(a, b)
        // — an unsound under-approximation that can also break monotone
        // convergence of the fixpoint.
        let all_keys: HashSet<&String> =
            self.bindings.keys().chain(other.bindings.keys()).collect();
        for key in all_keys {
            let val_self = self.get(key);
            let val_other = other.get(key);
            let widened = val_self.widen_with_thresholds(&val_other, thresholds);
            result.set(key.clone(), widened);
        }
        result
    }

    /// Check whether `self ⊑ other` (pointwise subset).
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        if !self.reachable {
            return true;
        }
        if !other.reachable {
            return false;
        }
        for (key, &v) in &self.bindings {
            let w = other.get(key);
            if !v.is_subset_of(&w) {
                return false;
            }
        }
        true
    }
}

impl Default for VsaEnv {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Abstract memory model
// ─────────────────────────────────────────────────────────────────────────────

/// A memory region tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryRegion {
    /// Stack frame of function at the given address (or 0 for the current fn).
    Stack(u64),
    /// The global data segment.
    Global,
    /// A heap allocation identified by its allocation site address.
    Heap(u64),
    /// The code segment (read-only for most purposes).
    Code,
    /// Unknown region (conservative: joins with any other region).
    Unknown,
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stack(a) => write!(f, "Stack({a:#x})"),
            Self::Global => write!(f, "Global"),
            Self::Heap(a) => write!(f, "Heap({a:#x})"),
            Self::Code => write!(f, "Code"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Key for a memory cell: a region + a strided interval of possible offsets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryCell {
    pub region: MemoryRegion,
    pub offset: u64,
    pub size_bytes: u8,
}

/// The abstract memory: a map from cells to strided intervals.
#[derive(Debug, Clone, Default)]
pub struct AbstractMemory {
    cells: HashMap<MemoryCell, StridedInterval>,
    /// Per-region *weak* value: the join of every value ever stored to the
    /// region through an IMPRECISE (non-singleton) offset. A precise/strong
    /// store overwrites a single cell, which would otherwise silently drop the
    /// contribution of an earlier imprecise store recorded at that same offset.
    /// Accumulating imprecise stores here (never overwritten by strong stores)
    /// and joining it into every load keeps loads a sound over-approximation of
    /// all values that could live in the region. `MemoryRegion::Unknown` here
    /// represents a weak store that may target any region.
    region_weak: HashMap<MemoryRegion, StridedInterval>,
}

impl AbstractMemory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Write `value` to cell `(region, offset, size)`.
    /// If the offset is uncertain, all cells in that region are clobbered.
    /// Maximum number of abstract memory cells tracked to prevent memory exhaustion.
    pub const MAX_CELLS: usize = 65_536;

    pub fn store(
        &mut self,
        region: MemoryRegion,
        offset: &StridedInterval,
        size_bytes: u8,
        value: StridedInterval,
    ) {
        if let Some(exact) = offset.as_singleton() {
            // Cap cell count before inserting a new singleton cell.
            if !self.cells.contains_key(&MemoryCell { region, offset: exact, size_bytes })
                && self.cells.len() >= Self::MAX_CELLS
            {
                // Cannot insert: join into all same-region cells conservatively.
                for (cell, stored) in &mut self.cells {
                    if cell.region == region {
                        *stored = stored.join(&value);
                    }
                }
                return;
            }
            let cell = MemoryCell { region, offset: exact, size_bytes };
            self.cells.insert(cell, value);
        } else {
            // Imprecise offset: strong update not possible — join into all matching cells.
            for (cell, stored) in &mut self.cells {
                if cell.region == region || region == MemoryRegion::Unknown {
                    *stored = stored.join(&value);
                }
            }
            // Record the value in the region's persistent weak accumulator so a
            // later strong store to the same offset cannot drop it (a generic
            // cell alone is not enough — it can be overwritten). Every load
            // joins this in, keeping the result a sound over-approximation.
            self.region_weak
                .entry(region)
                .and_modify(|e| *e = e.join(&value))
                .or_insert(value);
            // Also keep a generic cell for precision on subsequent precise loads.
            let lo = match offset {
                StridedInterval::Interval { lo, .. } => *lo,
                StridedInterval::Bottom => 0,
            };
            let cell = MemoryCell { region, offset: lo, size_bytes };
            self.cells
                .entry(cell)
                .and_modify(|e| *e = e.join(&value))
                .or_insert(value);
        }
    }

    /// Load from `(region, offset, size)`.
    /// An imprecise offset joins all matching cells.
    #[must_use]
    pub fn load(
        &self,
        region: MemoryRegion,
        offset: &StridedInterval,
        size_bytes: u8,
    ) -> StridedInterval {
        // `size_bytes` is attacker/decoder-controlled (derived from operand
        // width); guard against overflow (e.g. a bogus size_bytes > 31 would
        // overflow `u8` on `* 8`) by saturating and clamping to 64 bits.
        let bits = size_bytes.saturating_mul(8).min(64);
        // Weak contribution: any imprecise store to this region (or an
        // any-region `Unknown` weak store) could have written the loaded
        // location, so its value must always be over-approximated.
        let weak = self.region_weak_for(region);
        if let Some(exact) = offset.as_singleton() {
            let cell = MemoryCell { region, offset: exact, size_bytes };
            let precise = self
                .cells
                .get(&cell)
                .copied()
                .unwrap_or_else(|| StridedInterval::top(bits));
            return match weak {
                Some(w) => precise.join(&w),
                None => precise,
            };
        }
        // Imprecise: join all cells in the region plus the region weak value.
        let mut result = weak.unwrap_or(StridedInterval::Bottom);
        for (cell, &val) in &self.cells {
            if cell.region == region || region == MemoryRegion::Unknown {
                result = result.join(&val);
            }
        }
        if result.is_bottom() {
            StridedInterval::top(bits)
        } else {
            result
        }
    }

    /// The weak value applicable to a load from `region`: the region's own weak
    /// accumulator joined with the any-region (`Unknown`) weak accumulator.
    fn region_weak_for(&self, region: MemoryRegion) -> Option<StridedInterval> {
        let own = self.region_weak.get(&region).copied();
        let any = self.region_weak.get(&MemoryRegion::Unknown).copied();
        match (own, any) {
            (Some(a), Some(b)) => Some(a.join(&b)),
            (Some(a), None) => Some(a),
            (None, b) => b,
        }
    }

    /// Join two memory states element-wise.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (cell, &val) in &other.cells {
            result
                .cells
                .entry(cell.clone())
                .and_modify(|e| *e = e.join(&val))
                .or_insert(val);
        }
        for (region, &val) in &other.region_weak {
            result
                .region_weak
                .entry(*region)
                .and_modify(|e| *e = e.join(&val))
                .or_insert(val);
        }
        result
    }

    /// Widen element-wise.
    #[must_use]
    pub fn widen(&self, other: &Self, thresholds: &WideningThresholds) -> Self {
        let mut result = self.clone();
        for (cell, &val) in &other.cells {
            result
                .cells
                .entry(cell.clone())
                .and_modify(|e| *e = e.widen_with_thresholds(&val, thresholds))
                .or_insert(val);
        }
        for (region, &val) in &other.region_weak {
            result
                .region_weak
                .entry(*region)
                .and_modify(|e| *e = e.widen_with_thresholds(&val, thresholds))
                .or_insert(val);
        }
        result
    }

    /// Invalidate all cells in an unknown region (models an arbitrary store).
    pub fn clobber_unknown(&mut self, bits: u8) {
        for val in self.cells.values_mut() {
            *val = StridedInterval::top(bits);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Abstract instructions (IR)
// ─────────────────────────────────────────────────────────────────────────────

/// An operand in the abstract IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbstractOperand {
    /// A concrete constant.
    Const(u64, u8 /* bits */),
    /// A register / variable name.
    Var(String),
    /// A known strided interval (used for summaries and tests).
    Interval(StridedInterval),
}

/// An abstract instruction kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbstractInsnKind {
    // Assignments
    Assign { dst: String, src: AbstractOperand },
    // ALU binary
    Add { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    Sub { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    Mul { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    UDiv { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    SDiv { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    URem { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    And { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    Or  { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    Xor { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    Shl { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    Shr { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    Sar { dst: String, lhs: AbstractOperand, rhs: AbstractOperand },
    // ALU unary
    Not { dst: String, src: AbstractOperand },
    Neg { dst: String, src: AbstractOperand },
    // Bit manipulation
    ZeroExtend { dst: String, src: AbstractOperand, target_bits: u8 },
    SignExtend  { dst: String, src: AbstractOperand, target_bits: u8 },
    Truncate    { dst: String, src: AbstractOperand, target_bits: u8 },
    Extract     { dst: String, src: AbstractOperand, from_bit: u8, to_bit: u8 },
    Concat      { dst: String, hi: AbstractOperand, lo: AbstractOperand },
    // Memory
    Load  { dst: String, region: MemoryRegion, addr: AbstractOperand, size_bytes: u8 },
    Store { region: MemoryRegion, addr: AbstractOperand, size_bytes: u8, val: AbstractOperand },
    // Control
    Call  { callee: CallTarget, args: Vec<AbstractOperand>, returns: Vec<String> },
    Phi   { dst: String, srcs: Vec<String> },
}

/// The target of a call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallTarget {
    /// A known function at a static address.
    Static(u64),
    /// An indirect call through a register.
    Indirect(String),
    /// A library function identified by name.
    External(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Function summaries (inter-procedural)
// ─────────────────────────────────────────────────────────────────────────────

/// The summary of an analyzed function.
///
/// A summary records which registers are clobbered (set to Top) and which
/// return values are constrained to a known interval.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionSummary {
    /// The function's entry address.
    pub address: u64,
    /// Registers clobbered by this call (set to Top at the call site).
    pub clobbers: HashSet<String>,
    /// Return value intervals, indexed by return variable name (e.g., "rax").
    pub return_values: HashMap<String, StridedInterval>,
    /// Whether the function is a no-return (e.g., `exit`).
    pub no_return: bool,
    /// Whether the function modifies global / heap memory in an unknown way.
    pub clobbers_memory: bool,
}

impl FunctionSummary {
    /// Construct a totally conservative summary (everything unknown).
    #[must_use]
    pub fn unknown(address: u64, caller_saved: &[&str]) -> Self {
        let clobbers = caller_saved.iter().map(ToString::to_string).collect();
        Self {
            address,
            clobbers,
            return_values: HashMap::new(),
            no_return: false,
            clobbers_memory: true,
        }
    }

    /// Create a pure function summary (no side effects, result in `rax`).
    #[must_use]
    pub fn pure_fn(address: u64, result: StridedInterval) -> Self {
        let mut rv = HashMap::new();
        rv.insert("rax".to_string(), result);
        Self {
            address,
            clobbers: default_caller_saved(),
            return_values: rv,
            no_return: false,
            clobbers_memory: false,
        }
    }

    /// Create a no-return summary.
    #[must_use]
    pub fn no_return(address: u64) -> Self {
        let mut s = Self::unknown(address, &[]);
        s.no_return = true;
        s
    }

    /// Apply this summary to an environment, modelling the call effects.
    pub fn apply_to_env(
        &self,
        env: &mut VsaEnv,
        memory: &mut AbstractMemory,
        returns: &[String],
        bits: u8,
    ) {
        if self.no_return {
            env.reachable = false;
            return;
        }
        // Clobber caller-saved registers.
        for clobbered in &self.clobbers {
            env.set(clobbered.clone(), StridedInterval::top(bits));
        }
        // Install return values.
        for (ret_reg, &si) in &self.return_values {
            env.set(ret_reg.clone(), si);
        }
        // Propagate return values to declared return variables.
        // (Typically returns = ["rax"] or similar.)
        //
        // `return_values` is a `HashMap`, whose iteration order is
        // unspecified (and randomized per-process by `RandomState`). Indexing
        // into `.values()` positionally would therefore pick a different
        // register's interval on different runs whenever there is more than
        // one return value. Sort by register name first so the i-th slot is
        // deterministic and reproducible across runs.
        let mut sorted_values: Vec<(&String, &StridedInterval)> = self.return_values.iter().collect();
        sorted_values.sort_unstable_by(|a, b| a.0.cmp(b.0));
        for (i, ret_var) in returns.iter().enumerate() {
            if let Some(&(_, &si)) = sorted_values.get(i) {
                env.set(ret_var.clone(), si);
            } else {
                env.set(ret_var.clone(), StridedInterval::top(bits));
            }
        }
        // Clobber memory if the summary says so.
        if self.clobbers_memory {
            memory.clobber_unknown(bits);
        }
    }
}

/// Default x86-64 caller-saved registers.
fn default_caller_saved() -> HashSet<String> {
    ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
        .iter()
        .map(std::string::ToString::to_string)
        .collect()
}

/// A database of function summaries keyed by function address.
#[derive(Debug, Clone, Default)]
pub struct SummaryDatabase {
    summaries: HashMap<u64, FunctionSummary>,
    /// Summaries for external functions (by name).
    external: HashMap<String, FunctionSummary>,
}

impl SummaryDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, summary: FunctionSummary) {
        self.summaries.insert(summary.address, summary);
    }

    pub fn insert_external(&mut self, name: impl Into<String>, summary: FunctionSummary) {
        self.external.insert(name.into(), summary);
    }

    #[must_use]
    pub fn get_by_address(&self, addr: u64) -> Option<&FunctionSummary> {
        self.summaries.get(&addr)
    }

    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&FunctionSummary> {
        self.external.get(name)
    }

    /// Pre-populate with well-known libc functions.
    pub fn populate_libc_stubs(&mut self, bits: u8) {
        let malloc_result = StridedInterval::top(bits); // heap pointer
        self.insert_external("malloc", FunctionSummary::pure_fn(0, malloc_result));
        self.insert_external("calloc", FunctionSummary::pure_fn(0, malloc_result));
        self.insert_external("realloc", FunctionSummary::pure_fn(0, malloc_result));
        self.insert_external("free", FunctionSummary::unknown(0, &[]));
        self.insert_external("exit", FunctionSummary::no_return(0));
        self.insert_external("abort", FunctionSummary::no_return(0));
        // strlen returns [0, SIZE_MAX].
        let strlen_result = StridedInterval::range(0, u64::from(u32::MAX), bits);
        self.insert_external("strlen", FunctionSummary::pure_fn(0, strlen_result));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Abstract instruction interpreter
// ─────────────────────────────────────────────────────────────────────────────

/// Interpreter configuration.
#[derive(Debug, Clone)]
pub struct InterpreterConfig {
    /// Default bit-width for operations that don't specify one.
    pub default_bits: u8,
    /// Number of times a loop header is visited before widening kicks in.
    pub widen_delay: u32,
    /// Maximum total iterations before forcing convergence.
    pub max_iterations: u32,
    /// Widening thresholds to use.
    pub thresholds: WideningThresholds,
}

impl Default for InterpreterConfig {
    fn default() -> Self {
        Self {
            default_bits: 64,
            widen_delay: 3,
            max_iterations: 10_000,
            thresholds: WideningThresholds::default_thresholds(64),
        }
    }
}

/// The abstract instruction interpreter.
pub struct AbstractInterpreter<'a> {
    config: &'a InterpreterConfig,
    summaries: &'a SummaryDatabase,
}

impl<'a> AbstractInterpreter<'a> {
    #[must_use]
    pub const fn new(config: &'a InterpreterConfig, summaries: &'a SummaryDatabase) -> Self {
        Self { config, summaries }
    }

    /// Evaluate one operand in the context of `env`.
    #[must_use]
    pub fn eval_operand(&self, op: &AbstractOperand, env: &VsaEnv) -> StridedInterval {
        match op {
            AbstractOperand::Const(v, bits) => StridedInterval::singleton(*v, *bits),
            AbstractOperand::Var(name) => env.get(name),
            AbstractOperand::Interval(si) => *si,
        }
    }

    /// Execute a single abstract instruction, mutating `env` and `memory`.
    pub fn exec(
        &self,
        insn: &AbstractInsnKind,
        env: &mut VsaEnv,
        memory: &mut AbstractMemory,
    ) {
        use AbstractInsnKind::{
            Add, And, Assign, Call, Concat, Extract, Load, Mul, Neg, Not, Or, Phi,
            SDiv, Sar, Shl, Shr, SignExtend, Store, Sub, Truncate, UDiv, URem, Xor,
            ZeroExtend,
        };
        let bits = self.config.default_bits;

        match insn {
            Assign { dst, src } => {
                let v = self.eval_operand(src, env);
                env.set(dst.clone(), v);
            }
            Add { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::add),
            Sub { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::sub),
            Mul { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::mul),
            UDiv { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::udiv),
            SDiv { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::sdiv),
            URem { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::urem),
            And { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::band),
            Or  { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::bor),
            Xor { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::bxor),
            Shl { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::shl),
            Shr { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::shr),
            Sar { dst, lhs, rhs } => self.exec_binop(dst, lhs, rhs, env, StridedInterval::sar),
            Not { dst, src } => {
                let v = self.eval_operand(src, env);
                env.set(dst.clone(), v.bnot());
            }
            Neg { dst, src } => {
                let v = self.eval_operand(src, env);
                env.set(dst.clone(), v.neg());
            }
            ZeroExtend { dst, src, target_bits } => {
                let v = self.eval_operand(src, env);
                env.set(dst.clone(), v.zero_extend(*target_bits));
            }
            SignExtend { dst, src, target_bits } => {
                let v = self.eval_operand(src, env);
                env.set(dst.clone(), v.sign_extend(*target_bits));
            }
            Truncate { dst, src, target_bits } => {
                let v = self.eval_operand(src, env);
                env.set(dst.clone(), v.truncate(*target_bits));
            }
            Extract { dst, src, from_bit, to_bit } => {
                let v = self.eval_operand(src, env);
                env.set(dst.clone(), v.extract(*from_bit, *to_bit));
            }
            Concat { dst, hi, lo } => {
                let vh = self.eval_operand(hi, env);
                let vl = self.eval_operand(lo, env);
                env.set(dst.clone(), vh.concat(&vl));
            }
            Load { dst, region, addr, size_bytes } => {
                let addr_val = self.eval_operand(addr, env);
                let val = memory.load(*region, &addr_val, *size_bytes);
                env.set(dst.clone(), val);
            }
            Store { region, addr, size_bytes, val } => {
                let addr_val = self.eval_operand(addr, env);
                let stored = self.eval_operand(val, env);
                memory.store(*region, &addr_val, *size_bytes, stored);
            }
            Call { callee, args: _, returns } => {
                let summary = self.resolve_summary(callee);
                summary.apply_to_env(env, memory, returns, bits);
            }
            Phi { dst, srcs } => {
                let joined = srcs
                    .iter()
                    .map(|s| env.get(s))
                    .fold(StridedInterval::Bottom, |acc, si| acc.join(&si));
                env.set(dst.clone(), joined);
            }
        }
    }

    fn exec_binop(
        &self,
        dst: &str,
        lhs: &AbstractOperand,
        rhs: &AbstractOperand,
        env: &mut VsaEnv,
        op: fn(&StridedInterval, &StridedInterval) -> StridedInterval,
    ) {
        let a = self.eval_operand(lhs, env);
        let b = self.eval_operand(rhs, env);
        env.set(dst.to_owned(), op(&a, &b));
    }

    /// Resolve a call target to a summary.
    fn resolve_summary(&self, target: &CallTarget) -> FunctionSummary {
        match target {
            CallTarget::Static(addr) => {
                self.summaries
                    .get_by_address(*addr)
                    .cloned()
                    .unwrap_or_else(|| FunctionSummary::unknown(*addr, &[]))
            }
            CallTarget::External(name) => {
                self.summaries
                    .get_by_name(name)
                    .cloned()
                    .unwrap_or_else(|| FunctionSummary::unknown(0, &[]))
            }
            CallTarget::Indirect(_) => {
                // Totally unknown indirect call — clobber all caller-saved registers.
                FunctionSummary::unknown(
                    0,
                    &["rax", "rcx", "rdx", "r8", "r9", "r10", "r11",
                      "rsi", "rdi",
                      "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"],
                )
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CFG-level VSA pass
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block in the abstract CFG, ready for VSA.
#[derive(Debug, Clone)]
pub struct VsaBlock {
    /// Unique block identifier (typically the start address).
    pub id: u64,
    /// Instructions to execute in order.
    pub insns: Vec<AbstractInsnKind>,
    /// Successor block IDs.
    pub succs: Vec<u64>,
    /// Predecessor block IDs.
    pub preds: Vec<u64>,
    /// Whether this block is a loop header (triggers widening).
    pub is_loop_header: bool,
}

/// The result of a VSA run: per-block entry environments.
#[derive(Debug, Clone, Default)]
pub struct VsaResult {
    /// Environment at the *entry* of each block.
    pub entry_envs: HashMap<u64, VsaEnv>,
    /// Environment at the *exit* of each block.
    pub exit_envs: HashMap<u64, VsaEnv>,
    /// Memory state at the *exit* of each block.
    pub exit_memory: HashMap<u64, AbstractMemory>,
    /// Number of iterations performed.
    pub iterations: u32,
    /// Whether the analysis converged.
    pub converged: bool,
}

/// Statistics about the VSA run.
#[derive(Debug, Clone, Default)]
pub struct VsaStats {
    pub total_blocks: usize,
    pub iterations: u32,
    pub widened_blocks: u32,
    pub converged: bool,
}

/// Run VSA over a set of blocks in chaotic (worklist) iteration order.
pub fn run_vsa<S: BuildHasher>(
    entry_id: u64,
    blocks: &HashMap<u64, VsaBlock, S>,
    initial_env: VsaEnv,
    config: &InterpreterConfig,
    summaries: &SummaryDatabase,
) -> VsaResult {
    let interpreter = AbstractInterpreter::new(config, summaries);

    // Initialise per-block entry environments to Bottom.
    let mut entry_envs: HashMap<u64, VsaEnv> = HashMap::new();
    let mut exit_envs: HashMap<u64, VsaEnv> = HashMap::new();
    let mut exit_memory: HashMap<u64, AbstractMemory> = HashMap::new();
    let mut visit_count: HashMap<u64, u32> = HashMap::new();

    // Set entry environment.
    entry_envs.insert(entry_id, initial_env);

    // Worklist initialised with the entry block.
    let mut worklist: VecDeque<u64> = VecDeque::new();
    worklist.push_back(entry_id);

    let mut iterations = 0u32;

    while let Some(block_id) = worklist.pop_front() {
        if iterations >= config.max_iterations {
            break;
        }
        iterations += 1;

        let Some(block) = blocks.get(&block_id) else { continue };

        let env_in = entry_envs.get(&block_id).cloned().unwrap_or_else(VsaEnv::bottom);
        let mem_in = block
            .preds
            .iter()
            .filter_map(|pred_id| exit_memory.get(pred_id))
            .fold(None::<AbstractMemory>, |acc, m| acc.map_or_else(|| Some(m.clone()), |a| Some(a.join(m))))
            .unwrap_or_default();

        // Execute the block.
        let mut env_out = env_in.clone();
        let mut mem_out = mem_in.clone();
        for insn in &block.insns {
            interpreter.exec(insn, &mut env_out, &mut mem_out);
        }

        // Propagate to successors.
        for &succ_id in &block.succs {
            let old_entry = entry_envs.get(&succ_id).cloned().unwrap_or_else(VsaEnv::bottom);
            let new_entry = old_entry.join(&env_out);

            // Apply widening if this successor is a loop header and we've
            // visited it enough times.
            let vc = visit_count.entry(succ_id).or_insert(0);
            *vc += 1;

            let widened = if blocks.get(&succ_id).is_some_and(|b| b.is_loop_header)
                && *vc > config.widen_delay
            {
                old_entry.widen(&new_entry, &config.thresholds)
            } else {
                new_entry.clone()
            };

            if !widened.is_subset_of(&old_entry) || !old_entry.is_subset_of(&widened) {
                entry_envs.insert(succ_id, widened);
                if !worklist.contains(&succ_id) {
                    worklist.push_back(succ_id);
                }
            }
        }

        exit_envs.insert(block_id, env_out);
        exit_memory.insert(block_id, mem_out);
    }

    let converged = worklist.is_empty() && iterations < config.max_iterations;

    VsaResult { entry_envs, exit_envs, exit_memory, iterations, converged }
}

// ─────────────────────────────────────────────────────────────────────────────
// Value Set predicates
// ─────────────────────────────────────────────────────────────────────────────

/// Test whether a value set might satisfy `>= lo` (used for bounds-check elimination).
#[must_use]
pub const fn may_be_geq(si: &StridedInterval, lo: u64) -> bool {
    match si {
        StridedInterval::Bottom => false,
        StridedInterval::Interval { hi, .. } => *hi >= lo,
    }
}

/// Test whether a value set might satisfy `< hi`.
#[must_use]
pub const fn may_be_lt(si: &StridedInterval, hi_bound: u64) -> bool {
    match si {
        StridedInterval::Bottom => false,
        StridedInterval::Interval { lo, .. } => *lo < hi_bound,
    }
}

/// Test whether a value set is guaranteed to satisfy `< hi` (safe: no OOB).
#[must_use]
pub const fn must_be_lt(si: &StridedInterval, hi_bound: u64) -> bool {
    match si {
        StridedInterval::Bottom => true,
        StridedInterval::Interval { hi, .. } => *hi < hi_bound,
    }
}

/// Refine a value set with the knowledge that a comparison `val < bound` is
/// true at the branch target (conditional branch refinement).
#[must_use]
pub fn refine_lt(si: &StridedInterval, bound: u64) -> StridedInterval {
    match si {
        StridedInterval::Bottom => StridedInterval::Bottom,
        StridedInterval::Interval { stride, lo, hi, bits } => {
            if *lo >= bound {
                StridedInterval::Bottom
            } else {
                StridedInterval::new(*stride, *lo, (*hi).min(bound.saturating_sub(1)), *bits)
            }
        }
    }
}

/// Refine assuming the comparison `val >= bound` is true.
#[must_use]
pub fn refine_geq(si: &StridedInterval, bound: u64) -> StridedInterval {
    match si {
        StridedInterval::Bottom => StridedInterval::Bottom,
        StridedInterval::Interval { stride, lo, hi, bits } => {
            if *hi < bound {
                StridedInterval::Bottom
            } else {
                // Raise the lower bound to `bound`, but snap UP to the nearest
                // value that is still congruent to the original `lo` modulo
                // `stride`. Using `lo.max(bound)` directly would keep the old
                // stride from a shifted base, silently changing which residue
                // class the interval represents (e.g. evens {0,2,..} refined
                // `>=5` would become odds {5,7,..} — both wrong and unsound).
                let new_lo = align_lo_geq(*lo, *stride, bound);
                StridedInterval::new(*stride, new_lo, *hi, *bits)
            }
        }
    }
}

/// Smallest value `>= bound` that is congruent to `lo` modulo `stride`
/// (i.e. `lo + k*stride` for some `k >= 0`). Returns `lo` when `bound <= lo`.
#[must_use]
fn align_lo_geq(lo: u64, stride: u64, bound: u64) -> u64 {
    if bound <= lo {
        return lo;
    }
    let s = stride.max(1);
    // How far above `bound` the next `lo`-congruent value sits.
    let add = (lo % s + s - bound % s) % s;
    bound.saturating_add(add)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strided_interval::StridedInterval;

    #[test]
    fn refine_geq_preserves_strided_members() {
        // si = evens {0,2,4,6,8,10}; refine with `>= 5` must keep {6,8,10}
        // and drop nothing that satisfies the predicate. A naive
        // `lo = max(lo, bound)` reuses the original stride from a shifted
        // base, producing odds {5,7,9} — both wrong and unsound.
        let si = StridedInterval::new(2, 0, 10, 8);
        let r = refine_geq(&si, 5);
        for v in [6u64, 8, 10] {
            assert!(r.contains(v), "refine_geq dropped {v}: {si} >= 5 -> {r}");
        }
    }

    #[test]
    fn refine_geq_soundness_property() {
        use crate::test_prng::xorshift as xs;
        let mut state = 0x51de_f00d_1357_9bdfu64;
        for _ in 0..3000 {
            let lo = xs(&mut state) & 0xFF;
            let hi = xs(&mut state) & 0xFF;
            let stride = (xs(&mut state) % 6) + 1;
            let bound = xs(&mut state) & 0xFF;
            let si = StridedInterval::new(stride, lo.min(hi), lo.max(hi), 8);
            let r = refine_geq(&si, bound);
            for v in 0u64..=0xFF {
                if si.contains(v) && v >= bound {
                    assert!(r.contains(v), "refine_geq unsound: {si} >= {bound} dropped {v} -> {r}");
                }
            }
        }
    }

    fn make_config() -> InterpreterConfig {
        InterpreterConfig { default_bits: 64, ..Default::default() }
    }

    fn make_summaries() -> SummaryDatabase {
        let mut db = SummaryDatabase::new();
        db.populate_libc_stubs(64);
        db
    }

    #[test]
    fn test_load_imprecise_offset_large_size_bytes_no_overflow() {
        // `size_bytes` is decoder-derived; a bogus/oversized value (e.g. from
        // a malformed or adversarial operand-width field) must not overflow
        // the `u8` computation of `bits` (size_bytes * 8) — previously this
        // panicked in debug builds (or silently wrapped in release) for any
        // size_bytes > 31.
        let mem = AbstractMemory::new();
        let offset = StridedInterval::top(64); // imprecise offset
        let result = mem.load(MemoryRegion::Stack(0), &offset, 255);
        // With no cells stored, an imprecise load falls back to `top`; the
        // key assertion is that computing `bits` did not panic above.
        assert!(result.is_top() || result.is_bottom());
    }

    #[test]
    fn test_assign_and_add() {
        let config = make_config();
        let sums = make_summaries();
        let interp = AbstractInterpreter::new(&config, &sums);
        let mut env = VsaEnv::new();
        let mut mem = AbstractMemory::new();

        interp.exec(
            &AbstractInsnKind::Assign {
                dst: "x".into(),
                src: AbstractOperand::Const(5, 64),
            },
            &mut env,
            &mut mem,
        );
        interp.exec(
            &AbstractInsnKind::Add {
                dst: "y".into(),
                lhs: AbstractOperand::Var("x".into()),
                rhs: AbstractOperand::Const(3, 64),
            },
            &mut env,
            &mut mem,
        );
        let y = env.get("y");
        assert_eq!(y.as_singleton(), Some(8));
    }

    #[test]
    fn test_load_store() {
        let config = make_config();
        let sums = make_summaries();
        let interp = AbstractInterpreter::new(&config, &sums);
        let mut env = VsaEnv::new();
        let mut mem = AbstractMemory::new();

        // Store 42 at stack offset 0.
        interp.exec(
            &AbstractInsnKind::Store {
                region: MemoryRegion::Stack(0),
                addr: AbstractOperand::Const(0, 64),
                size_bytes: 8,
                val: AbstractOperand::Const(42, 64),
            },
            &mut env,
            &mut mem,
        );
        // Load it back.
        interp.exec(
            &AbstractInsnKind::Load {
                dst: "z".into(),
                region: MemoryRegion::Stack(0),
                addr: AbstractOperand::Const(0, 64),
                size_bytes: 8,
            },
            &mut env,
            &mut mem,
        );
        let z = env.get("z");
        assert_eq!(z.as_singleton(), Some(42));
    }

    #[test]
    fn test_env_join() {
        let a = {
            let mut e = VsaEnv::new();
            e.set("x", StridedInterval::singleton(1, 64));
            e
        };
        let b = {
            let mut e = VsaEnv::new();
            e.set("x", StridedInterval::singleton(2, 64));
            e
        };
        let c = a.join(&b);
        let x = c.get("x");
        assert!(x.contains(1));
        assert!(x.contains(2));
    }

    #[test]
    fn test_refine_lt() {
        let si = StridedInterval::range(0, 100, 64);
        let refined = refine_lt(&si, 50);
        assert!(!refined.contains(50));
        assert!(refined.contains(49));
    }

    #[test]
    fn test_call_clobbers_rax() {
        let config = make_config();
        let sums = make_summaries();
        let interp = AbstractInterpreter::new(&config, &sums);
        let mut env = VsaEnv::new();
        let mut mem = AbstractMemory::new();
        env.set("rax", StridedInterval::singleton(42, 64));

        interp.exec(
            &AbstractInsnKind::Call {
                callee: CallTarget::Indirect("rcx".into()),
                args: vec![],
                returns: vec![],
            },
            &mut env,
            &mut mem,
        );
        // After an indirect call, rax should be Top (unknown).
        let rax = env.get("rax");
        assert!(rax.is_top());
    }

    #[test]
    fn test_simple_worklist_vsa() {
        // Build a tiny CFG: entry -> body -> exit
        let entry_insns = vec![AbstractInsnKind::Assign {
            dst: "i".into(),
            src: AbstractOperand::Const(0, 64),
        }];
        let body_insns = vec![AbstractInsnKind::Add {
            dst: "i".into(),
            lhs: AbstractOperand::Var("i".into()),
            rhs: AbstractOperand::Const(1, 64),
        }];

        let entry_block = VsaBlock { id: 0, insns: entry_insns, succs: vec![1], preds: vec![], is_loop_header: false };
        let body_block = VsaBlock { id: 1, insns: body_insns, succs: vec![2], preds: vec![0], is_loop_header: false };
        let exit_block = VsaBlock { id: 2, insns: vec![], succs: vec![], preds: vec![1], is_loop_header: false };

        let mut blocks = HashMap::new();
        blocks.insert(0, entry_block);
        blocks.insert(1, body_block);
        blocks.insert(2, exit_block);

        let config = make_config();
        let sums = make_summaries();
        let result = run_vsa(0, &blocks, VsaEnv::new(), &config, &sums);

        assert!(result.converged);
        // At exit, i should be 1.
        let exit_env = result.exit_envs.get(&1).unwrap();
        let i = exit_env.get("i");
        assert_eq!(i.as_singleton(), Some(1));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Randomized soundness properties for AbstractMemory / VsaEnv / exec.
//
// The contract under test: a load must OVER-APPROXIMATE every value that could
// have been stored to an aliasing cell. We check this against a brute-force
// concrete shadow memory using a small xorshift PRNG (no external dev-deps).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod prop_soundness {
    use super::*;
    use crate::strided_interval::StridedInterval;
    use std::collections::HashMap;

    use crate::test_prng::Xs;

    // ── Strong-update store/load: singleton store, singleton load ───────────
    // After a sequence of singleton stores, a singleton load from an offset
    // that was written must return exactly the last value stored there, and
    // (soundness) must contain that concrete value.
    #[test]
    fn prop_singleton_store_load_matches_shadow() {
        let mut r = Xs::new(0xF00D_1234);
        for _ in 0..2000 {
            let mut mem = AbstractMemory::new();
            let mut shadow: HashMap<u64, u64> = HashMap::new();
            let nstores = 1 + (r.next() % 8);
            for _ in 0..nstores {
                let off = r.next() % 16; // small offset space -> overwrites
                let val = r.next() % 1000;
                mem.store(
                    MemoryRegion::Stack(0),
                    &StridedInterval::singleton(off, 64),
                    8,
                    StridedInterval::singleton(val, 64),
                );
                shadow.insert(off, val);
            }
            for (&off, &val) in &shadow {
                let loaded = mem.load(
                    MemoryRegion::Stack(0),
                    &StridedInterval::singleton(off, 64),
                    8,
                );
                assert!(
                    loaded.contains(val),
                    "singleton load dropped stored value {val} at off {off}: {loaded:?}"
                );
            }
        }
    }

    // Imprecise load over-approximates every live stored cell in the region.
    #[test]
    fn prop_imprecise_load_contains_all_live_cells() {
        let mut r = Xs::new(0x1357_9BDF);
        for _ in 0..2000 {
            let mut mem = AbstractMemory::new();
            let mut shadow: HashMap<u64, u64> = HashMap::new();
            let nstores = 1 + (r.next() % 10);
            for _ in 0..nstores {
                let off = r.next() % 32;
                let val = r.next() % 1000;
                mem.store(
                    MemoryRegion::Stack(0),
                    &StridedInterval::singleton(off, 64),
                    8,
                    StridedInterval::singleton(val, 64),
                );
                shadow.insert(off, val);
            }
            let loaded = mem.load(MemoryRegion::Stack(0), &StridedInterval::top(64), 8);
            for (&off, &val) in &shadow {
                assert!(
                    loaded.contains(val) || loaded.is_top(),
                    "imprecise load dropped live value {val}@{off}: {loaded:?}"
                );
            }
        }
    }

    // ── Memory join soundness: load after join over-approximates both ───────
    #[test]
    fn prop_memory_join_over_approximates_both() {
        let mut r = Xs::new(0x2468_ACE0);
        for _ in 0..2000 {
            let mk = |r: &mut Xs| {
                let mut m = AbstractMemory::new();
                let mut sh: HashMap<u64, u64> = HashMap::new();
                for _ in 0..(1 + r.next() % 5) {
                    let off = r.next() % 16;
                    let val = r.next() % 500;
                    m.store(
                        MemoryRegion::Stack(0),
                        &StridedInterval::singleton(off, 64),
                        8,
                        StridedInterval::singleton(val, 64),
                    );
                    sh.insert(off, val);
                }
                (m, sh)
            };
            let (ma, sha) = mk(&mut r);
            let (mb, shb) = mk(&mut r);
            let mj = ma.join(&mb);
            // For any offset present in exactly one side, the joined load at
            // that singleton offset must contain that side's value.
            for (side, sh) in [(&ma, &sha), (&mb, &shb)] {
                let _ = side;
                for (&off, &val) in sh {
                    // Only offsets unique to one map give a clean check; if both
                    // wrote the same offset the join is a superset anyway.
                    let other_has = if std::ptr::eq(sh, &sha) {
                        shb.get(&off)
                    } else {
                        sha.get(&off)
                    };
                    let loaded = mj.load(
                        MemoryRegion::Stack(0),
                        &StridedInterval::singleton(off, 64),
                        8,
                    );
                    // joined load must contain this side's value AND the other's if any.
                    assert!(
                        loaded.contains(val) || loaded.is_top(),
                        "joined load dropped {val}@{off}: {loaded:?}"
                    );
                    if let Some(&ov) = other_has {
                        assert!(
                            loaded.contains(ov) || loaded.is_top(),
                            "joined load dropped other side {ov}@{off}: {loaded:?}"
                        );
                    }
                }
            }
        }
    }

    // ── VsaEnv join is a lattice upper bound (per-variable over-approx) ─────
    #[test]
    fn prop_vsaenv_join_over_approximates() {
        let mut r = Xs::new(0x9E37_79B9);
        let vars = ["a", "b", "c", "d"];
        for _ in 0..3000 {
            let mk = |r: &mut Xs| {
                let mut e = VsaEnv::new();
                for v in &vars {
                    if !r.next().is_multiple_of(3) {
                        let lo = r.next() % 200;
                        let hi = lo + r.next() % 200;
                        e.set(*v, StridedInterval::range(lo, hi, 64));
                    }
                }
                e
            };
            let a = mk(&mut r);
            let b = mk(&mut r);
            let j = a.join(&b);
            for v in &vars {
                let av = a.get(v);
                let bv = b.get(v);
                let jv = j.get(v);
                assert!(av.is_subset_of(&jv), "join lost lhs {v}: {av:?} ⊄ {jv:?}");
                assert!(bv.is_subset_of(&jv), "join lost rhs {v}: {bv:?} ⊄ {jv:?}");
            }
            assert!(a.is_subset_of(&j) && b.is_subset_of(&j), "env join not upper bound");
        }
    }

    // ── exec transfer soundness: add of two singletons is exact; add of
    // ranges over-approximates every concrete sum (delegates to StridedInterval,
    // but we verify the interpreter wiring end-to-end). ─────────────────────
    #[test]
    fn prop_exec_add_over_approximates_concrete() {
        let config = InterpreterConfig { default_bits: 64, ..Default::default() };
        let sums = SummaryDatabase::new();
        let interp = AbstractInterpreter::new(&config, &sums);
        let mut r = Xs::new(0x0102_0304);
        for _ in 0..3000 {
            let alo = r.next() % 10_000;
            let ahi = alo + r.next() % 10_000;
            let blo = r.next() % 10_000;
            let bhi = blo + r.next() % 10_000;
            let mut env = VsaEnv::new();
            let mut mem = AbstractMemory::new();
            env.set("a", StridedInterval::range(alo, ahi, 64));
            env.set("b", StridedInterval::range(blo, bhi, 64));
            interp.exec(
                &AbstractInsnKind::Add {
                    dst: "c".into(),
                    lhs: AbstractOperand::Var("a".into()),
                    rhs: AbstractOperand::Var("b".into()),
                },
                &mut env,
                &mut mem,
            );
            let c = env.get("c");
            for &x in &[alo, ahi] {
                for &y in &[blo, bhi] {
                    assert!(
                        c.contains(x.wrapping_add(y)) || c.is_top(),
                        "exec add missed {x}+{y}: {c:?}"
                    );
                }
            }
        }
    }

    // ── An unknown / indirect call must clobber caller-saved regs to Top ────
    #[test]
    fn prop_indirect_call_clobbers_to_top() {
        let config = InterpreterConfig { default_bits: 64, ..Default::default() };
        let sums = SummaryDatabase::new();
        let interp = AbstractInterpreter::new(&config, &sums);
        let mut env = VsaEnv::new();
        let mut mem = AbstractMemory::new();
        for reg in ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"] {
            env.set(reg, StridedInterval::singleton(7, 64));
        }
        interp.exec(
            &AbstractInsnKind::Call {
                callee: CallTarget::Indirect("rbx".into()),
                args: vec![],
                returns: vec![],
            },
            &mut env,
            &mut mem,
        );
        // Every value the register held before must still be representable.
        for reg in ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"] {
            assert!(env.get(reg).is_top(), "reg {reg} not clobbered to Top after indirect call");
        }
    }

    // ── Concrete-shadow memory soundness across the strong/weak boundary ─────
    // A single concrete execution: each abstract store also writes ONE concrete
    // (offset, value) into a shadow map — the concrete offset is drawn from the
    // stored offset interval (possibly imprecise) and the concrete value from
    // the stored value interval. After the sequence, a singleton load at every
    // shadow offset MUST over-approximate (contain) the concrete value that
    // lives there. This exercises the strong-update (singleton) / weak-update
    // (imprecise-offset) boundary against a ground-truth reference.
    #[test]
    fn prop_memory_shadow_soundness_with_imprecise_offsets() {
        let mut r = Xs::new(0xBEEF_C0DE_1234);
        const REGION: MemoryRegion = MemoryRegion::Stack(0);
        for _ in 0..5000 {
            let mut mem = AbstractMemory::new();
            let mut shadow: HashMap<u64, u64> = HashMap::new();
            let nstores = 1 + (r.next() % 12);
            for _ in 0..nstores {
                // Offset: half the time a singleton (strong), else imprecise.
                let base = r.next() % 16;
                let (off_si, coff) = if r.next().is_multiple_of(2) {
                    (StridedInterval::singleton(base, 64), base)
                } else {
                    let span = 1 + r.next() % 8;
                    let hi = (base + span).min(23);
                    // Concrete offset picked within [base, hi].
                    let coff = base + (r.next() % (hi - base + 1));
                    (StridedInterval::range(base, hi, 64), coff)
                };
                // Value: half singleton, else a range; concrete drawn from it.
                let vbase = r.next() % 1000;
                let (val_si, cval) = if r.next().is_multiple_of(2) {
                    (StridedInterval::singleton(vbase, 64), vbase)
                } else {
                    let vspan = 1 + r.next() % 200;
                    let cval = vbase + (r.next() % (vspan + 1));
                    (StridedInterval::range(vbase, vbase + vspan, 64), cval)
                };
                mem.store(REGION, &off_si, 8, val_si);
                shadow.insert(coff, cval);
            }
            for (&off, &val) in &shadow {
                let loaded = mem.load(REGION, &StridedInterval::singleton(off, 64), 8);
                assert!(
                    loaded.contains(val) || loaded.is_top(),
                    "shadow soundness: load@{off} lost concrete {val}: {loaded:?}"
                );
            }
            // An imprecise (Top-offset) load must over-approximate EVERY live cell.
            let wide = mem.load(REGION, &StridedInterval::top(64), 8);
            for (&off, &val) in &shadow {
                assert!(
                    wide.contains(val) || wide.is_top(),
                    "imprecise load lost concrete {val}@{off}: {wide:?}"
                );
            }
        }
    }

    // ── Random CFG generator (small, with back-edges & loop headers) ─────────
    fn rand_cfg(r: &mut Xs) -> (HashMap<u64, VsaBlock>, u64) {
        let n = 2 + (r.next() % 4) as u64; // 2..=5 blocks
        // Build succs first so we can compute preds.
        let mut succs: HashMap<u64, Vec<u64>> = HashMap::new();
        for id in 0..n {
            let mut ss = Vec::new();
            let k = r.next() % 3; // 0..=2 successors
            for _ in 0..k {
                let t = r.next() % n; // ANY block, including <= id (back-edge)
                if !ss.contains(&t) {
                    ss.push(t);
                }
            }
            succs.insert(id, ss);
        }
        let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
        for id in 0..n {
            preds.insert(id, Vec::new());
        }
        for (&src, ss) in &succs {
            for &d in ss {
                preds.get_mut(&d).unwrap().push(src);
            }
        }
        let mut blocks = HashMap::new();
        for id in 0..n {
            // A few instructions: increment a shared counter to stress widening.
            let mut insns = Vec::new();
            match r.next() % 3 {
                0 => insns.push(AbstractInsnKind::Assign {
                    dst: "i".into(),
                    src: AbstractOperand::Const(r.next() % 8, 64),
                }),
                1 => insns.push(AbstractInsnKind::Add {
                    dst: "i".into(),
                    lhs: AbstractOperand::Var("i".into()),
                    rhs: AbstractOperand::Const(1 + r.next() % 4, 64),
                }),
                _ => insns.push(AbstractInsnKind::Add {
                    dst: "j".into(),
                    lhs: AbstractOperand::Var("i".into()),
                    rhs: AbstractOperand::Var("j".into()),
                }),
            }
            // Mark a block a loop header if it has a predecessor with id >= itself
            // (i.e. it is the target of a back-edge).
            let is_loop_header = preds[&id].iter().any(|&p| p >= id);
            blocks.insert(
                id,
                VsaBlock {
                    id,
                    insns,
                    succs: succs[&id].clone(),
                    preds: preds[&id].clone(),
                    is_loop_header,
                },
            );
        }
        (blocks, 0)
    }

    // The worklist fixpoint must TERMINATE (converge) on random CFGs with
    // back-edges thanks to widening at loop headers.
    #[test]
    fn prop_run_vsa_converges_on_random_cfgs() {
        let mut r = Xs::new(0xC0FF_EE00_5A5A);
        let config = InterpreterConfig { default_bits: 64, ..Default::default() };
        let sums = SummaryDatabase::new();
        for _ in 0..2000 {
            let (blocks, entry) = rand_cfg(&mut r);
            let result = run_vsa(entry, &blocks, VsaEnv::new(), &config, &sums);
            assert!(
                result.converged,
                "run_vsa failed to converge (iters={}) on CFG with {} blocks",
                result.iterations,
                blocks.len()
            );
        }
    }

    // Soundness: the fixpoint at a merge must over-approximate concrete
    // execution along each incoming path. Diamond CFG: entry -> {b1, b2} -> b3.
    #[test]
    fn prop_run_vsa_sound_at_merge() {
        let config = InterpreterConfig { default_bits: 64, ..Default::default() };
        let sums = SummaryDatabase::new();
        let mut r = Xs::new(0x1122_3344_5566);
        for _ in 0..2000 {
            let c1 = r.next() % 500;
            let c2 = r.next() % 500;
            let entry = VsaBlock {
                id: 0,
                insns: vec![],
                succs: vec![1, 2],
                preds: vec![],
                is_loop_header: false,
            };
            let b1 = VsaBlock {
                id: 1,
                insns: vec![AbstractInsnKind::Assign {
                    dst: "x".into(),
                    src: AbstractOperand::Const(c1, 64),
                }],
                succs: vec![3],
                preds: vec![0],
                is_loop_header: false,
            };
            let b2 = VsaBlock {
                id: 2,
                insns: vec![AbstractInsnKind::Assign {
                    dst: "x".into(),
                    src: AbstractOperand::Const(c2, 64),
                }],
                succs: vec![3],
                preds: vec![0],
                is_loop_header: false,
            };
            let b3 = VsaBlock {
                id: 3,
                insns: vec![],
                succs: vec![],
                preds: vec![1, 2],
                is_loop_header: false,
            };
            let mut blocks = HashMap::new();
            for b in [entry, b1, b2, b3] {
                blocks.insert(b.id, b);
            }
            let result = run_vsa(0, &blocks, VsaEnv::new(), &config, &sums);
            assert!(result.converged);
            let merge = result.entry_envs.get(&3).expect("merge env");
            let x = merge.get("x");
            assert!(x.contains(c1), "merge env lost path-1 value {c1}: {x:?}");
            assert!(x.contains(c2), "merge env lost path-2 value {c2}: {x:?}");
        }
    }

    // Soundness under a loop with widening: a counter loop must, at the loop
    // header, over-approximate every concrete counter value it can take.
    #[test]
    fn prop_run_vsa_loop_over_approximates_counter() {
        let config = InterpreterConfig { default_bits: 64, ..Default::default() };
        let sums = SummaryDatabase::new();
        // entry: i=0 -> header(loop) -> body: i=i+1 -> back to header; header->exit
        let entry = VsaBlock {
            id: 0,
            insns: vec![AbstractInsnKind::Assign {
                dst: "i".into(),
                src: AbstractOperand::Const(0, 64),
            }],
            succs: vec![1],
            preds: vec![],
            is_loop_header: false,
        };
        let header = VsaBlock {
            id: 1,
            insns: vec![],
            succs: vec![2, 3],
            preds: vec![0, 2],
            is_loop_header: true,
        };
        let body = VsaBlock {
            id: 2,
            insns: vec![AbstractInsnKind::Add {
                dst: "i".into(),
                lhs: AbstractOperand::Var("i".into()),
                rhs: AbstractOperand::Const(1, 64),
            }],
            succs: vec![1],
            preds: vec![1],
            is_loop_header: false,
        };
        let exit = VsaBlock {
            id: 3,
            insns: vec![],
            succs: vec![],
            preds: vec![1],
            is_loop_header: false,
        };
        let mut blocks = HashMap::new();
        for b in [entry, header, body, exit] {
            blocks.insert(b.id, b);
        }
        let result = run_vsa(0, &blocks, VsaEnv::new(), &config, &sums);
        assert!(result.converged, "loop VSA did not converge");
        let hdr = result.entry_envs.get(&1).expect("header env");
        let i = hdr.get("i");
        // Concrete counter takes 0,1,2,3,... — all must be contained.
        for k in 0u64..20 {
            assert!(i.contains(k), "loop header env dropped concrete counter {k}: {i:?}");
        }
    }

    // ── Concrete interpreter for the same block ops ──────────────────────────
    fn concrete_eval(op: &AbstractOperand, st: &HashMap<String, u64>) -> u64 {
        match op {
            AbstractOperand::Const(v, _) => *v,
            AbstractOperand::Var(n) => *st.get(n).unwrap_or(&0),
            AbstractOperand::Interval(si) => si.as_singleton().unwrap_or(0),
        }
    }

    fn concrete_exec(insn: &AbstractInsnKind, st: &mut HashMap<String, u64>) {
        match insn {
            AbstractInsnKind::Assign { dst, src } => {
                let v = concrete_eval(src, st);
                st.insert(dst.clone(), v);
            }
            AbstractInsnKind::Add { dst, lhs, rhs } => {
                let v = concrete_eval(lhs, st).wrapping_add(concrete_eval(rhs, st));
                st.insert(dst.clone(), v);
            }
            AbstractInsnKind::Sub { dst, lhs, rhs } => {
                let v = concrete_eval(lhs, st).wrapping_sub(concrete_eval(rhs, st));
                st.insert(dst.clone(), v);
            }
            _ => {}
        }
    }

    // The fixpoint must be a sound over-approximation of a concrete execution
    // along a real path: for every block the concrete walk lands on, the
    // abstract entry environment must CONTAIN the concrete register values.
    //
    // The regs "i" and "j" are initialised to 0 both concretely and in the
    // initial abstract env, so the base case holds; soundness of each transfer
    // function then propagates the invariant inductively across every edge the
    // concrete walk takes (including back-edges through widened loop headers).
    #[test]
    fn prop_run_vsa_sound_along_concrete_path() {
        let config = InterpreterConfig { default_bits: 64, ..Default::default() };
        let sums = SummaryDatabase::new();
        let mut r = Xs::new(0x5EED_1234_ABCD);
        for _ in 0..3000 {
            let (blocks, entry) = rand_cfg(&mut r);
            let mut init = VsaEnv::new();
            init.set("i", StridedInterval::singleton(0, 64));
            init.set("j", StridedInterval::singleton(0, 64));
            let result = run_vsa(entry, &blocks, init, &config, &sums);
            // Only a converged fixpoint is claimed sound; the generator + widening
            // guarantee convergence (checked separately), but guard anyway.
            if !result.converged {
                continue;
            }
            // Concrete random walk from the entry block.
            let mut st: HashMap<String, u64> = HashMap::new();
            st.insert("i".into(), 0);
            st.insert("j".into(), 0);
            let mut cur = entry;
            for _step in 0..60 {
                let Some(block) = blocks.get(&cur) else { break };
                // Invariant: abstract entry env over-approximates concrete state.
                let env = result
                    .entry_envs
                    .get(&cur)
                    .unwrap_or_else(|| panic!("no entry env for reachable block {cur}"));
                for (reg, &cval) in &st {
                    let av = env.get(reg);
                    assert!(
                        av.contains(cval),
                        "unsound: block {cur} reg {reg} concrete {cval} not in abstract {av:?}"
                    );
                }
                for insn in &block.insns {
                    concrete_exec(insn, &mut st);
                }
                if block.succs.is_empty() {
                    break;
                }
                let pick = (r.next() as usize) % block.succs.len();
                cur = block.succs[pick];
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Randomized lattice property tests for VsaEnv (join / widen soundness)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod env_lattice_props {
    use super::*;
    use crate::strided_interval::{StridedInterval, WideningThresholds};

    use crate::test_prng::xorshift;

    fn rand_si8(state: &mut u64) -> StridedInterval {
        let lo = xorshift(state) & 0xFF;
        let hi = xorshift(state) & 0xFF;
        let stride = (xorshift(state) % 4) + 1;
        StridedInterval::new(stride, lo.min(hi), lo.max(hi), 8)
    }

    /// Random env over a subset of a small variable universe (so that key
    /// asymmetries between the two operands are exercised).
    fn rand_env(state: &mut u64) -> VsaEnv {
        let vars = ["a", "b", "c", "d"];
        let mut env = VsaEnv::new();
        for v in vars {
            if !xorshift(state).is_multiple_of(3) {
                env.set(v, rand_si8(state));
            }
        }
        env
    }

    fn elements8(si: &StridedInterval) -> Vec<u64> {
        (0u64..=0xFF).filter(|&v| si.contains(v)).collect()
    }

    #[test]
    fn prop_env_join_commutative() {
        let mut state = 0xE21F_0123_4567_89AB;
        for _ in 0..2000 {
            let a = rand_env(&mut state);
            let b = rand_env(&mut state);
            let ab = a.join(&b);
            let ba = b.join(&a);
            for v in ["a", "b", "c", "d"] {
                assert_eq!(ab.get(v), ba.get(v), "env join not commutative on {v}");
            }
        }
    }

    #[test]
    fn prop_env_join_sound() {
        // Every concrete value of every variable of each operand must be
        // contained in the join.
        let mut state = 0x50D4_ABCD_EF01_2345;
        for _ in 0..2000 {
            let a = rand_env(&mut state);
            let b = rand_env(&mut state);
            let j = a.join(&b);
            for env in [&a, &b] {
                for v in ["a", "b", "c", "d"] {
                    for cv in elements8(&env.get(v)) {
                        assert!(
                            j.get(v).contains(cv),
                            "env join lost {v}={cv}: {:?} vs {:?} -> {:?}",
                            a.get(v), b.get(v), j.get(v)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn prop_env_widen_over_approximates_join() {
        // widen(a, b) ⊒ join(a, b), pointwise. Seed 0x51DE: caught the old
        // implementation iterating only `other`'s keys, which silently dropped
        // (to Bottom) any binding present solely in `self`.
        let thr = WideningThresholds::default_thresholds(8);
        let mut state = 0x51DE_1111_2222_3333;
        for _ in 0..2000 {
            let a = rand_env(&mut state);
            let b = rand_env(&mut state);
            let j = a.join(&b);
            let w = a.widen(&b, &thr);
            for v in ["a", "b", "c", "d"] {
                for cv in elements8(&j.get(v)) {
                    assert!(
                        w.get(v).contains(cv),
                        "env widen below join on {v}={cv}: a={:?} b={:?} join={:?} widen={:?}",
                        a.get(v), b.get(v), j.get(v), w.get(v)
                    );
                }
            }
        }
    }

    #[test]
    fn env_widen_regression_key_only_in_self() {
        // Direct regression for the key-drop bug found by
        // prop_env_widen_over_approximates_join.
        let thr = WideningThresholds::default_thresholds(8);
        let mut a = VsaEnv::new();
        a.set("x", StridedInterval::new(1, 3, 7, 8));
        let b = VsaEnv::new(); // no binding for "x"
        let w = a.widen(&b, &thr);
        for cv in 3u64..=7 {
            assert!(
                w.get("x").contains(cv),
                "widen dropped self-only binding x={cv}: {:?}",
                w.get("x")
            );
        }
    }
}
