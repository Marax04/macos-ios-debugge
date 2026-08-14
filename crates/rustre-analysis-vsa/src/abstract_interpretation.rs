//! `abstract_interpretation` — abstract interpretation framework for VSA.
//!
//! Provides:
//! * [`AbstractDomain`]      — trait all domains must implement.
//! * [`ConstantDomain`]      — flat constant-value domain.
//! * [`IntervalDomain`]      — closed integer-interval domain [lo, hi].
//! * [`SignDomain`]          — sign domain: Neg / Zero / Pos / Top / Bot.
//! * [`AbstractState`]       — per-program-point map of var → abstract value.
//! * [`TransferFunction`]    — per-instruction semantics in an abstract domain.
//! * [`Fixpoint`]            — worklist-based fixpoint iterator.
//! * [`AbstractInterpreter`] — top-level coordinator.

use std::collections::{HashMap, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// AbstractDomain trait
// ─────────────────────────────────────────────────────────────────────────────

/// Core trait for an abstract domain lattice.
///
/// All operations must be monotone and terminate (ascending chain condition
/// is enforced by the widening operator in `widen`).
pub trait AbstractDomain: Clone + PartialEq + fmt::Debug {
    /// Bottom element — no information (least element of the lattice).
    fn bottom() -> Self;

    /// Top element — all possible values (greatest element).
    fn top() -> Self;

    /// Least upper bound (join) of two elements.
    #[must_use]
    fn join(&self, other: &Self) -> Self;

    /// Greatest lower bound (meet).
    #[must_use]
    fn meet(&self, other: &Self) -> Self;

    /// Widening operator to enforce termination. Default: join.
    #[must_use]
    fn widen(&self, other: &Self) -> Self {
        self.join(other)
    }

    /// Returns `true` when `self ⊑ other` (self is less-or-equal in the lattice).
    fn leq(&self, other: &Self) -> bool {
        self.join(other) == *other
    }

    /// Returns `true` when this element is the bottom.
    fn is_bottom(&self) -> bool {
        self == &Self::bottom()
    }

    /// Returns `true` when this element is the top.
    fn is_top(&self) -> bool {
        self == &Self::top()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantDomain
// ─────────────────────────────────────────────────────────────────────────────

/// Flat constant-value domain for 64-bit integers.
///
/// Lattice:  Bot ⊑ Const(n) ⊑ Top  (all Const(n) are incomparable).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstantDomain {
    Bottom,
    Const(i64),
    Top,
}

impl fmt::Display for ConstantDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bottom => write!(f, "⊥"),
            Self::Const(c) => write!(f, "{c}"),
            Self::Top => write!(f, "⊤"),
        }
    }
}

impl ConstantDomain {
    #[must_use] 
    pub const fn of(v: i64) -> Self {
        Self::Const(v)
    }

    #[must_use] 
    pub const fn as_const(&self) -> Option<i64> {
        if let Self::Const(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Arithmetic addition, preserving lattice ordering.
    #[must_use] 
    pub const fn add(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Const(a), Self::Const(b)) => Self::Const(a.wrapping_add(*b)),
        }
    }

    /// Arithmetic subtraction.
    #[must_use] 
    pub const fn sub(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Const(a), Self::Const(b)) => Self::Const(a.wrapping_sub(*b)),
        }
    }

    /// Multiplication.
    #[must_use] 
    pub const fn mul(&self, other: &Self) -> Self {
        match (self, other) {
            // Bottom FIRST, matching `add`/`sub` above. Bottom means
            // unreachable, so γ(⊥) = ∅ and the product set is empty regardless
            // of the other operand. Matching the `Const(0)` short-circuit ahead
            // of it made `0 * ⊥` evaluate to `Const(0)`, resurrecting a dead
            // value and breaking strictness the rest of the domain relies on.
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Const(0), _) | (_, Self::Const(0)) => Self::Const(0),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Const(a), Self::Const(b)) => Self::Const(a.wrapping_mul(*b)),
        }
    }
}

impl AbstractDomain for ConstantDomain {
    fn bottom() -> Self {
        Self::Bottom
    }
    fn top() -> Self {
        Self::Top
    }

    fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => x.clone(),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Const(a), Self::Const(b)) => {
                if a == b {
                    self.clone()
                } else {
                    Self::Top
                }
            }
        }
    }

    fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Top, x) | (x, Self::Top) => x.clone(),
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Const(a), Self::Const(b)) => {
                if a == b {
                    self.clone()
                } else {
                    Self::Bottom
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IntervalDomain
// ─────────────────────────────────────────────────────────────────────────────

/// Closed integer-interval domain `[lo, hi]`.
///
/// `lo > hi` is the bottom element.  `[-∞, +∞]` is the top element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntervalDomain {
    pub lo: i64,
    pub hi: i64,
}

impl IntervalDomain {
    pub const MIN: i64 = i64::MIN;
    pub const MAX: i64 = i64::MAX;

    #[must_use] 
    pub const fn single(v: i64) -> Self {
        Self { lo: v, hi: v }
    }

    #[must_use] 
    pub const fn range(lo: i64, hi: i64) -> Self {
        Self { lo, hi }
    }

    #[must_use] 
    pub fn contains(&self, v: i64) -> bool {
        !self.is_bottom() && v >= self.lo && v <= self.hi
    }

    #[must_use] 
    pub fn size(&self) -> Option<u64> {
        if self.is_bottom() {
            None
        } else {
            Some(self.hi.wrapping_sub(self.lo).wrapping_add(1).cast_unsigned())
        }
    }

    #[must_use] 
    pub fn add(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        let lo = self.lo.saturating_add(other.lo);
        let hi = self.hi.saturating_add(other.hi);
        Self { lo, hi }
    }

    #[must_use] 
    pub fn sub(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        let lo = self.lo.saturating_sub(other.hi);
        let hi = self.hi.saturating_sub(other.lo);
        Self { lo, hi }
    }
}

impl fmt::Display for IntervalDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_bottom() {
            return write!(f, "⊥");
        }
        if self.lo == Self::MIN && self.hi == Self::MAX {
            return write!(f, "⊤");
        }
        write!(f, "[{}, {}]", self.lo, self.hi)
    }
}

impl AbstractDomain for IntervalDomain {
    fn bottom() -> Self {
        Self { lo: 1, hi: 0 }
    } // lo > hi ↔ empty
    fn top() -> Self {
        Self {
            lo: Self::MIN,
            hi: Self::MAX,
        }
    }

    fn join(&self, other: &Self) -> Self {
        if self.is_bottom() {
            return other.clone();
        }
        if other.is_bottom() {
            return self.clone();
        }
        Self {
            lo: self.lo.min(other.lo),
            hi: self.hi.max(other.hi),
        }
    }

    fn meet(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        let lo = self.lo.max(other.lo);
        let hi = self.hi.min(other.hi);
        if lo > hi {
            Self::bottom()
        } else {
            Self { lo, hi }
        }
    }

    fn widen(&self, other: &Self) -> Self {
        if self.is_bottom() {
            return other.clone();
        }
        if other.is_bottom() {
            return self.clone();
        }
        let lo = if other.lo < self.lo {
            Self::MIN
        } else {
            self.lo
        };
        let hi = if other.hi > self.hi {
            Self::MAX
        } else {
            self.hi
        };
        Self { lo, hi }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignDomain
// ─────────────────────────────────────────────────────────────────────────────

/// Three-valued sign domain: `Bot ⊑ Neg | Zero | Pos ⊑ Top`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignDomain {
    Bottom,
    Neg,
    Zero,
    Pos,
    Top,
}

impl fmt::Display for SignDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Bottom => "⊥",
            Self::Neg => "neg",
            Self::Zero => "zero",
            Self::Pos => "pos",
            Self::Top => "⊤",
        };
        f.write_str(s)
    }
}

impl SignDomain {
    #[must_use] 
    pub const fn of(v: i64) -> Self {
        if v < 0 {
            Self::Neg
        } else if v == 0 {
            Self::Zero
        } else {
            Self::Pos
        }
    }

    #[must_use] 
    pub const fn add(&self, other: &Self) -> Self {
        use SignDomain::{Bottom, Zero, Pos, Neg, Top};
        match (self, other) {
            (Bottom, _) | (_, Bottom) => Bottom,
            (Zero, x) | (x, Zero) => *x,
            (Pos, Pos) => Pos,
            (Neg, Neg) => Neg,
            _ => Top,
        }
    }

    #[must_use] 
    pub const fn neg(&self) -> Self {
        match self {
            Self::Neg => Self::Pos,
            Self::Pos => Self::Neg,
            x => *x,
        }
    }
}

impl AbstractDomain for SignDomain {
    fn bottom() -> Self {
        Self::Bottom
    }
    fn top() -> Self {
        Self::Top
    }

    fn join(&self, other: &Self) -> Self {
        use SignDomain::{Bottom, Top};
        if self == other {
            return *self;
        }
        match (self, other) {
            (Bottom, x) | (x, Bottom) => *x,
            _ => Top,
        }
    }

    fn meet(&self, other: &Self) -> Self {
        use SignDomain::{Top, Bottom};
        if self == other {
            return *self;
        }
        match (self, other) {
            (Top, x) | (x, Top) => *x,
            _ => Bottom,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AbstractState
// ─────────────────────────────────────────────────────────────────────────────

/// A per-program-point abstract state: maps variable names to abstract values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractState<D: AbstractDomain> {
    pub map: HashMap<String, D>,
}

impl<D: AbstractDomain> AbstractState<D> {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn get(&self, var: &str) -> D {
        self.map.get(var).cloned().unwrap_or_else(D::bottom)
    }

    pub fn set(&mut self, var: impl Into<String>, val: D) {
        self.map.insert(var.into(), val);
    }

    /// Join with another state (pointwise).
    #[must_use] 
    pub fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (k, v) in &other.map {
            let old = result.get(k);
            result.set(k.clone(), old.join(v));
        }
        result
    }

    /// Pointwise widening.
    #[must_use] 
    pub fn widen(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (k, v) in &other.map {
            let old = result.get(k);
            result.set(k.clone(), old.widen(v));
        }
        result
    }

    /// True when `self ⊑ other` pointwise.
    #[must_use] 
    pub fn leq(&self, other: &Self) -> bool {
        for (k, v) in &self.map {
            let o = other.get(k);
            if !v.leq(&o) {
                return false;
            }
        }
        true
    }
}

impl<D: AbstractDomain> Default for AbstractState<D> {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Abstract instruction model
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified instruction for abstract interpretation.
#[derive(Debug, Clone)]
pub enum AbstractInstr {
    /// `dst = const(val)`.
    Const { dst: String, val: i64 },
    /// `dst = lhs + rhs`.
    Add {
        dst: String,
        lhs: String,
        rhs: String,
    },
    /// `dst = lhs - rhs`.
    Sub {
        dst: String,
        lhs: String,
        rhs: String,
    },
    /// `dst = phi(sources...)`.
    Phi { dst: String, sources: Vec<String> },
    /// Unconditional jump to `target`.
    Jump { target: usize },
    /// Conditional jump: `cond != 0` → `true_t`, else `false_t`.
    CondJump {
        cond: String,
        true_t: usize,
        false_t: usize,
    },
    /// Return.
    Ret,
    /// No-op.
    Nop,
}

/// A basic block for abstract interpretation.
#[derive(Debug, Clone)]
pub struct AbsBlock {
    pub id: usize,
    pub instrs: Vec<AbstractInstr>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

impl AbsBlock {
    #[must_use] 
    pub const fn new(id: usize, instrs: Vec<AbstractInstr>) -> Self {
        Self {
            id,
            instrs,
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }
}

/// A program for abstract interpretation.
#[derive(Debug, Clone)]
pub struct AbsProgram {
    pub blocks: Vec<AbsBlock>,
    pub entry: usize,
}

impl AbsProgram {
    #[must_use] 
    pub const fn new(entry: usize) -> Self {
        Self {
            blocks: Vec::new(),
            entry,
        }
    }

    pub fn add_block(&mut self, block: AbsBlock) {
        self.blocks.push(block);
    }

    pub fn add_edge(&mut self, from: usize, to: usize) {
        if let Some(b) = self.blocks.iter_mut().find(|b| b.id == from)
            && !b.successors.contains(&to) {
                b.successors.push(to);
            }
        if let Some(b) = self.blocks.iter_mut().find(|b| b.id == to)
            && !b.predecessors.contains(&from) {
                b.predecessors.push(from);
            }
    }

    #[must_use] 
    pub fn block(&self, id: usize) -> Option<&AbsBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TransferFunction
// ─────────────────────────────────────────────────────────────────────────────

/// Transfer function: applies one instruction to an abstract state.
pub struct TransferFunction;

impl TransferFunction {
    /// Apply `instr` to `state` using the constant domain.
    #[must_use] 
    pub fn apply_const(
        instr: &AbstractInstr,
        state: &AbstractState<ConstantDomain>,
    ) -> AbstractState<ConstantDomain> {
        let mut out = state.clone();
        match instr {
            AbstractInstr::Const { dst, val } => {
                out.set(dst.clone(), ConstantDomain::Const(*val));
            }
            AbstractInstr::Add { dst, lhs, rhs } => {
                let a = state.get(lhs);
                let b = state.get(rhs);
                out.set(dst.clone(), a.add(&b));
            }
            AbstractInstr::Sub { dst, lhs, rhs } => {
                let a = state.get(lhs);
                let b = state.get(rhs);
                out.set(dst.clone(), a.sub(&b));
            }
            AbstractInstr::Phi { dst, sources } => {
                let joined = sources
                    .iter()
                    .fold(ConstantDomain::Bottom, |acc, src| acc.join(&state.get(src)));
                out.set(dst.clone(), joined);
            }
            // Control-flow and no-ops define no value: state passes through.
            AbstractInstr::Jump { .. }
            | AbstractInstr::CondJump { .. }
            | AbstractInstr::Ret
            | AbstractInstr::Nop => {}
        }
        out
    }

    /// Apply `instr` to `state` using the interval domain.
    #[must_use] 
    pub fn apply_interval(
        instr: &AbstractInstr,
        state: &AbstractState<IntervalDomain>,
    ) -> AbstractState<IntervalDomain> {
        let mut out = state.clone();
        match instr {
            AbstractInstr::Const { dst, val } => {
                out.set(dst.clone(), IntervalDomain::single(*val));
            }
            AbstractInstr::Add { dst, lhs, rhs } => {
                let a = state.get(lhs);
                let b = state.get(rhs);
                out.set(dst.clone(), a.add(&b));
            }
            AbstractInstr::Sub { dst, lhs, rhs } => {
                let a = state.get(lhs);
                let b = state.get(rhs);
                out.set(dst.clone(), a.sub(&b));
            }
            AbstractInstr::Phi { dst, sources } => {
                let joined = sources.iter().fold(IntervalDomain::bottom(), |acc, src| {
                    acc.join(&state.get(src))
                });
                out.set(dst.clone(), joined);
            }
            // Control-flow and no-ops define no value: state passes through.
            AbstractInstr::Jump { .. }
            | AbstractInstr::CondJump { .. }
            | AbstractInstr::Ret
            | AbstractInstr::Nop => {}
        }
        out
    }

    /// Apply `instr` to `state` using the sign domain.
    #[must_use] 
    pub fn apply_sign(
        instr: &AbstractInstr,
        state: &AbstractState<SignDomain>,
    ) -> AbstractState<SignDomain> {
        let mut out = state.clone();
        match instr {
            AbstractInstr::Const { dst, val } => {
                out.set(dst.clone(), SignDomain::of(*val));
            }
            AbstractInstr::Add { dst, lhs, rhs } => {
                let a = state.get(lhs);
                let b = state.get(rhs);
                out.set(dst.clone(), a.add(&b));
            }
            AbstractInstr::Phi { dst, sources } => {
                let joined = sources
                    .iter()
                    .fold(SignDomain::Bottom, |acc, src| acc.join(&state.get(src)));
                out.set(dst.clone(), joined);
            }
            AbstractInstr::Sub { dst, lhs, rhs } => {
                let a = state.get(lhs);
                let b = state.get(rhs);
                out.set(dst.clone(), a.add(&b.neg()));
            }
            // Remaining variants define no value; they cannot leave a stale
            // sign on any destination.
            AbstractInstr::Jump { .. } | AbstractInstr::CondJump { .. }
            | AbstractInstr::Ret
            | AbstractInstr::Nop => {}
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixpoint
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a fixpoint computation.
#[derive(Debug, Clone)]
pub struct FixpointResult<D: AbstractDomain> {
    /// Pre-state for each block.
    pub pre: HashMap<usize, AbstractState<D>>,
    /// Post-state for each block.
    pub post: HashMap<usize, AbstractState<D>>,
    /// Number of iterations until convergence.
    pub iterations: usize,
}

/// Worklist-based fixpoint iterator for abstract interpretation.
pub struct Fixpoint;

impl Fixpoint {
    /// Run fixpoint on `program` using the constant domain transfer function.
    #[must_use] 
    pub fn run_const(program: &AbsProgram, use_widening: bool) -> FixpointResult<ConstantDomain> {
        Self::run_generic(
            program,
            AbstractState::<ConstantDomain>::new,
            TransferFunction::apply_const,
            use_widening,
        )
    }

    /// Run fixpoint using the interval domain.
    #[must_use] 
    pub fn run_interval(
        program: &AbsProgram,
        use_widening: bool,
    ) -> FixpointResult<IntervalDomain> {
        Self::run_generic(
            program,
            AbstractState::<IntervalDomain>::new,
            TransferFunction::apply_interval,
            use_widening,
        )
    }

    /// Run fixpoint using the sign domain.
    #[must_use] 
    pub fn run_sign(program: &AbsProgram, use_widening: bool) -> FixpointResult<SignDomain> {
        Self::run_generic(
            program,
            AbstractState::<SignDomain>::new,
            TransferFunction::apply_sign,
            use_widening,
        )
    }

    fn run_generic<D, Init, Transfer>(
        program: &AbsProgram,
        init: Init,
        transfer: Transfer,
        use_widening: bool,
    ) -> FixpointResult<D>
    where
        D: AbstractDomain,
        Init: Fn() -> AbstractState<D>,
        Transfer: Fn(&AbstractInstr, &AbstractState<D>) -> AbstractState<D>,
    {
        const MAX_ITER: usize = 10_000;
        let mut pre: HashMap<usize, AbstractState<D>> = HashMap::new();
        let mut post: HashMap<usize, AbstractState<D>> = HashMap::new();
        // Track which blocks have been processed at least once so we don't
        // skip the first-iteration transfer-function application when both
        // old_pre and merged are the initial (empty/Bottom) state.
        let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();

        for b in &program.blocks {
            pre.insert(b.id, init());
            post.insert(b.id, init());
        }

        let mut worklist: VecDeque<usize> = program.blocks.iter().map(|b| b.id).collect();
        let mut iterations = 0;

        while let Some(bid) = worklist.pop_front() {
            iterations += 1;
            if iterations > MAX_ITER {
                break;
            }

            let Some(block) = program.block(bid) else { continue };

            // in_state = join of post-states of predecessors.
            let in_state: AbstractState<D> = if block.predecessors.is_empty() {
                init()
            } else {
                let mut acc = init();
                for &pred in &block.predecessors {
                    match post.get(&pred) {
                        Some(p) => acc = acc.join(p),
                        None => acc = acc.join(&init()),
                    }
                }
                acc
            };

            // Widening vs plain join.
            let merged = if use_widening {
                pre.get(&bid)
                    .map_or_else(|| in_state.clone(), |old| old.widen(&in_state))
            } else {
                in_state
            };

            let unchanged = visited.contains(&bid)
                && pre
                    .get(&bid)
                    .is_some_and(|old_pre| merged.leq(old_pre) && old_pre.leq(&merged));
            if unchanged {
                // No change since last visit — skip transfer-function re-application.
                continue;
            }
            visited.insert(bid);
            pre.insert(bid, merged.clone());

            // Apply transfer function to all instructions.
            let mut state = merged;
            for instr in &block.instrs {
                state = transfer(instr, &state);
            }

            let post_changed = post
                .get(&bid)
                .is_none_or(|old_post| !state.leq(old_post) || !old_post.leq(&state));
            if post_changed {
                post.insert(bid, state);
                for &succ in &block.successors {
                    worklist.push_back(succ);
                }
            } else {
                post.insert(bid, state);
            }
        }

        FixpointResult {
            pre,
            post,
            iterations,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AbstractInterpreter — top-level coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of an abstract interpretation run.
#[derive(Debug, Clone)]
pub struct InterpreterSummary {
    pub iterations: usize,
    pub const_vars: Vec<(usize, String, i64)>,
    pub always_positive: Vec<(usize, String)>,
    pub always_negative: Vec<(usize, String)>,
}

/// Top-level abstract interpreter coordinator.
pub struct AbstractInterpreter;

impl AbstractInterpreter {
    /// Analyse a program with the constant domain.
    #[must_use] 
    pub fn run_constants(
        program: &AbsProgram,
    ) -> (FixpointResult<ConstantDomain>, InterpreterSummary) {
        let result = Fixpoint::run_const(program, false);
        let mut const_vars = Vec::new();
        for (&bid, state) in &result.post {
            for (var, val) in &state.map {
                if let ConstantDomain::Const(c) = val {
                    const_vars.push((bid, var.clone(), *c));
                }
            }
        }
        let iterations = result.iterations;
        let summary = InterpreterSummary {
            iterations,
            const_vars,
            always_positive: Vec::new(),
            always_negative: Vec::new(),
        };
        (result, summary)
    }

    /// Analyse a program with the sign domain.
    #[must_use] 
    pub fn run_signs(program: &AbsProgram) -> (FixpointResult<SignDomain>, InterpreterSummary) {
        let result = Fixpoint::run_sign(program, false);
        let mut pos = Vec::new();
        let mut neg = Vec::new();
        for (&bid, state) in &result.post {
            for (var, val) in &state.map {
                match val {
                    SignDomain::Pos => pos.push((bid, var.clone())),
                    SignDomain::Neg => neg.push((bid, var.clone())),
                    // Not a definite sign: contributes to neither summary list.
                    SignDomain::Bottom | SignDomain::Zero | SignDomain::Top => {}
                }
            }
        }
        let iterations = result.iterations;
        let summary = InterpreterSummary {
            iterations,
            const_vars: Vec::new(),
            always_positive: pos,
            always_negative: neg,
        };
        (result, summary)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prop_sign_domain_add_is_sound() {
        // For all concrete x,y, SignDomain::of(x+y) must be <= (join with)
        // SignDomain::of(x).add(of(y)) — i.e. the abstract add over-approximates.
        // The domain models mathematical integers (no machine wraparound), so
        // only exercise sums that don't overflow i64 — a wrapping sum is not
        // part of the concrete semantics this domain abstracts.
        let samples: [i64; 7] = [i64::MIN, -1000, -1, 0, 1, 1000, i64::MAX];
        for &x in &samples {
            for &y in &samples {
                let Some(concrete_val) = x.checked_add(y) else { continue };
                let abstract_sum = SignDomain::of(x).add(&SignDomain::of(y));
                let concrete = SignDomain::of(concrete_val);
                // concrete sign must be represented: either equal or the
                // abstract result is Top (which represents everything).
                assert!(
                    abstract_sum == concrete || abstract_sum == SignDomain::Top,
                    "sign add unsound: of({x})+of({y}) = {abstract_sum}, concrete {concrete}"
                );
            }
        }
    }

    #[test]
    fn prop_interval_add_sub_over_approximate() {
        fn xs(s: &mut u64) -> u64 {
            let mut v = *s; v ^= v << 13; v ^= v >> 7; v ^= v << 17; *s = v; v
        }
        let mut state = 0x2718_2818_2845_9045u64;
        for _ in 0..3000 {
            let a1 = (xs(&mut state) % 4000) as i64 - 2000;
            let a2 = (xs(&mut state) % 4000) as i64 - 2000;
            let b1 = (xs(&mut state) % 4000) as i64 - 2000;
            let b2 = (xs(&mut state) % 4000) as i64 - 2000;
            let a = IntervalDomain::range(a1.min(a2), a1.max(a2));
            let b = IntervalDomain::range(b1.min(b2), b1.max(b2));
            let sum = a.add(&b);
            let dif = a.sub(&b);
            for &x in &[a1.min(a2), a1.max(a2)] {
                for &y in &[b1.min(b2), b1.max(b2)] {
                    assert!(sum.contains(x + y), "interval add missed {x}+{y}: {a}+{b} -> {sum}");
                    assert!(dif.contains(x - y), "interval sub missed {x}-{y}: {a}-{b} -> {dif}");
                }
            }
        }
    }

    fn make_simple_program() -> AbsProgram {
        // BB0: x = 5; y = x + 3   →   BB1: ret
        let mut p = AbsProgram::new(0);
        p.add_block(AbsBlock::new(
            0,
            vec![
                AbstractInstr::Const {
                    dst: "x".into(),
                    val: 5,
                },
                AbstractInstr::Add {
                    dst: "y".into(),
                    lhs: "x".into(),
                    rhs: "x".into(),
                },
            ],
        ));
        p.add_block(AbsBlock::new(1, vec![AbstractInstr::Ret]));
        p.add_edge(0, 1);
        p
    }

    fn make_loop_program() -> AbsProgram {
        // BB0: i=0 → BB1 (header): phi(i,j), j=i+1 → BB1 (back) or BB2 (exit)
        let mut p = AbsProgram::new(0);
        p.add_block(AbsBlock::new(
            0,
            vec![AbstractInstr::Const {
                dst: "i".into(),
                val: 0,
            }],
        ));
        p.add_block(AbsBlock::new(
            1,
            vec![
                AbstractInstr::Phi {
                    dst: "k".into(),
                    sources: vec!["i".into(), "j".into()],
                },
                AbstractInstr::Add {
                    dst: "j".into(),
                    lhs: "k".into(),
                    rhs: "k".into(),
                },
                AbstractInstr::CondJump {
                    cond: "j".into(),
                    true_t: 1,
                    false_t: 2,
                },
            ],
        ));
        p.add_block(AbsBlock::new(2, vec![AbstractInstr::Ret]));
        p.add_edge(0, 1);
        p.add_edge(1, 1); // back edge
        p.add_edge(1, 2);
        p
    }

    // 1. ConstantDomain::bottom and top.
    #[test]
    fn test_const_domain_extremes() {
        assert_eq!(ConstantDomain::bottom(), ConstantDomain::Bottom);
        assert_eq!(ConstantDomain::top(), ConstantDomain::Top);
    }

    // 2. ConstantDomain::join.
    #[test]
    fn test_const_domain_join() {
        assert_eq!(
            ConstantDomain::Const(5).join(&ConstantDomain::Const(5)),
            ConstantDomain::Const(5)
        );
        assert_eq!(
            ConstantDomain::Const(5).join(&ConstantDomain::Const(3)),
            ConstantDomain::Top
        );
        assert_eq!(
            ConstantDomain::Bottom.join(&ConstantDomain::Const(7)),
            ConstantDomain::Const(7)
        );
    }

    // 3. ConstantDomain::meet.
    #[test]
    fn test_const_domain_meet() {
        assert_eq!(
            ConstantDomain::Top.meet(&ConstantDomain::Const(4)),
            ConstantDomain::Const(4)
        );
        assert_eq!(
            ConstantDomain::Const(3).meet(&ConstantDomain::Const(4)),
            ConstantDomain::Bottom
        );
    }

    // 4. ConstantDomain arithmetic.
    #[test]
    fn test_const_domain_add() {
        let a = ConstantDomain::Const(3);
        let b = ConstantDomain::Const(7);
        assert_eq!(a.add(&b), ConstantDomain::Const(10));
        assert_eq!(ConstantDomain::Top.add(&b), ConstantDomain::Top);
        assert_eq!(ConstantDomain::Bottom.add(&b), ConstantDomain::Bottom);
    }

    // 5. ConstantDomain mul by zero.
    #[test]
    fn test_const_domain_mul_zero() {
        assert_eq!(
            ConstantDomain::Top.mul(&ConstantDomain::Const(0)),
            ConstantDomain::Const(0)
        );
    }

    // 6. IntervalDomain bottom/top.
    #[test]
    fn test_interval_extremes() {
        assert!(IntervalDomain::bottom().is_bottom());
        assert!(IntervalDomain::top().is_top());
    }

    // 7. IntervalDomain::contains.
    #[test]
    fn test_interval_contains() {
        let iv = IntervalDomain::range(0, 10);
        assert!(iv.contains(5));
        assert!(!iv.contains(11));
        assert!(!IntervalDomain::bottom().contains(0));
    }

    // 8. IntervalDomain join.
    #[test]
    fn test_interval_join() {
        let a = IntervalDomain::range(0, 5);
        let b = IntervalDomain::range(3, 10);
        let j = a.join(&b);
        assert_eq!(j.lo, 0);
        assert_eq!(j.hi, 10);
    }

    // 9. IntervalDomain meet.
    #[test]
    fn test_interval_meet() {
        let a = IntervalDomain::range(0, 10);
        let b = IntervalDomain::range(5, 15);
        let m = a.meet(&b);
        assert_eq!(m.lo, 5);
        assert_eq!(m.hi, 10);
    }

    // 10. IntervalDomain meet disjoint → bottom.
    #[test]
    fn test_interval_meet_disjoint() {
        let a = IntervalDomain::range(0, 3);
        let b = IntervalDomain::range(5, 10);
        assert!(a.meet(&b).is_bottom());
    }

    // 11. IntervalDomain add.
    #[test]
    fn test_interval_add() {
        let a = IntervalDomain::range(1, 3);
        let b = IntervalDomain::range(2, 4);
        let r = a.add(&b);
        assert_eq!(r.lo, 3);
        assert_eq!(r.hi, 7);
    }

    // 12. IntervalDomain widen.
    #[test]
    fn test_interval_widen() {
        let a = IntervalDomain::range(0, 5);
        let b = IntervalDomain::range(0, 10);
        let w = a.widen(&b);
        assert_eq!(w.hi, IntervalDomain::MAX);
    }

    // 13. SignDomain basics.
    #[test]
    fn test_sign_domain_of() {
        assert_eq!(SignDomain::of(-1), SignDomain::Neg);
        assert_eq!(SignDomain::of(0), SignDomain::Zero);
        assert_eq!(SignDomain::of(1), SignDomain::Pos);
    }

    // 14. SignDomain join.
    #[test]
    fn test_sign_domain_join() {
        assert_eq!(SignDomain::Pos.join(&SignDomain::Pos), SignDomain::Pos);
        assert_eq!(SignDomain::Pos.join(&SignDomain::Neg), SignDomain::Top);
        assert_eq!(SignDomain::Bottom.join(&SignDomain::Zero), SignDomain::Zero);
    }

    // 15. SignDomain meet.
    #[test]
    fn test_sign_domain_meet() {
        assert_eq!(SignDomain::Top.meet(&SignDomain::Pos), SignDomain::Pos);
        assert_eq!(SignDomain::Pos.meet(&SignDomain::Neg), SignDomain::Bottom);
    }

    // 16. SignDomain add.
    #[test]
    fn test_sign_domain_add() {
        assert_eq!(SignDomain::Pos.add(&SignDomain::Pos), SignDomain::Pos);
        assert_eq!(SignDomain::Neg.add(&SignDomain::Pos), SignDomain::Top);
        assert_eq!(SignDomain::Zero.add(&SignDomain::Pos), SignDomain::Pos);
    }

    // 17. AbstractState join.
    #[test]
    fn test_abstract_state_join() {
        let mut s1 = AbstractState::<ConstantDomain>::new();
        s1.set("x", ConstantDomain::Const(3));
        let mut s2 = AbstractState::<ConstantDomain>::new();
        s2.set("x", ConstantDomain::Const(5));
        let j = s1.join(&s2);
        assert_eq!(j.get("x"), ConstantDomain::Top);
    }

    // 18. AbstractState leq.
    #[test]
    fn test_abstract_state_leq() {
        let mut s1 = AbstractState::<ConstantDomain>::new();
        s1.set("x", ConstantDomain::Const(3));
        let mut s2 = AbstractState::<ConstantDomain>::new();
        s2.set("x", ConstantDomain::Top);
        assert!(s1.leq(&s2));
        assert!(!s2.leq(&s1));
    }

    // 19. TransferFunction::apply_const.
    #[test]
    fn test_transfer_const() {
        let state = AbstractState::<ConstantDomain>::new();
        let instr = AbstractInstr::Const {
            dst: "x".into(),
            val: 42,
        };
        let out = TransferFunction::apply_const(&instr, &state);
        assert_eq!(out.get("x"), ConstantDomain::Const(42));
    }

    // 20. TransferFunction::apply_const add.
    #[test]
    fn test_transfer_add() {
        let mut state = AbstractState::<ConstantDomain>::new();
        state.set("a", ConstantDomain::Const(10));
        state.set("b", ConstantDomain::Const(20));
        let instr = AbstractInstr::Add {
            dst: "c".into(),
            lhs: "a".into(),
            rhs: "b".into(),
        };
        let out = TransferFunction::apply_const(&instr, &state);
        assert_eq!(out.get("c"), ConstantDomain::Const(30));
    }

    // 21. TransferFunction sign.
    #[test]
    fn test_transfer_sign_const() {
        let state = AbstractState::<SignDomain>::new();
        let instr = AbstractInstr::Const {
            dst: "x".into(),
            val: -5,
        };
        let out = TransferFunction::apply_sign(&instr, &state);
        assert_eq!(out.get("x"), SignDomain::Neg);
    }

    // 22. Fixpoint::run_const simple.
    #[test]
    fn test_fixpoint_const_simple() {
        let p = make_simple_program();
        let r = Fixpoint::run_const(&p, false);
        // After BB0, y = x + x = 5 + 5 = 10.
        let post0 = r.post.get(&0).unwrap();
        assert_eq!(post0.get("x"), ConstantDomain::Const(5));
        assert_eq!(post0.get("y"), ConstantDomain::Const(10));
    }

    // 23. Fixpoint::run_sign simple.
    #[test]
    fn test_fixpoint_sign_simple() {
        let p = make_simple_program();
        let r = Fixpoint::run_sign(&p, false);
        let post0 = r.post.get(&0).unwrap();
        assert_eq!(post0.get("x"), SignDomain::Pos);
        assert_eq!(post0.get("y"), SignDomain::Pos);
    }

    // 24. Fixpoint: loop with widening terminates.
    #[test]
    fn test_fixpoint_loop_widening_terminates() {
        let p = make_loop_program();
        let r = Fixpoint::run_interval(&p, true);
        // Should terminate without exceeding MAX_ITER.
        assert!(r.iterations < 10_000);
    }

    // 25. Fixpoint::run_interval simple.
    #[test]
    fn test_fixpoint_interval() {
        let p = make_simple_program();
        let r = Fixpoint::run_interval(&p, false);
        let post0 = r.post.get(&0).unwrap();
        assert_eq!(post0.get("x"), IntervalDomain::single(5));
    }

    // 26. AbstractInterpreter::run_constants.
    #[test]
    fn test_interpreter_constants() {
        let p = make_simple_program();
        let (_result, summary) = AbstractInterpreter::run_constants(&p);
        let has_x = summary
            .const_vars
            .iter()
            .any(|(_, v, c)| v == "x" && *c == 5);
        assert!(
            has_x,
            "expected x=5 in const_vars: {:?}",
            summary.const_vars
        );
    }

    // 27. AbstractInterpreter::run_signs.
    #[test]
    fn test_interpreter_signs() {
        let p = make_simple_program();
        let (_, summary) = AbstractInterpreter::run_signs(&p);
        assert!(summary.always_positive.iter().any(|(_, v)| v == "x"));
    }

    // 28. ConstantDomain leq.
    #[test]
    fn test_const_domain_leq() {
        assert!(ConstantDomain::Bottom.leq(&ConstantDomain::Const(3)));
        assert!(ConstantDomain::Const(3).leq(&ConstantDomain::Top));
        assert!(!ConstantDomain::Top.leq(&ConstantDomain::Const(3)));
    }

    // 29. IntervalDomain::size.
    #[test]
    fn test_interval_size() {
        let iv = IntervalDomain::range(0, 9);
        assert_eq!(iv.size(), Some(10));
        assert_eq!(IntervalDomain::bottom().size(), None);
    }

    // 30. SignDomain neg.
    #[test]
    fn test_sign_neg() {
        assert_eq!(SignDomain::Pos.neg(), SignDomain::Neg);
        assert_eq!(SignDomain::Neg.neg(), SignDomain::Pos);
        assert_eq!(SignDomain::Zero.neg(), SignDomain::Zero);
    }

    // 31. IntervalDomain sub.
    #[test]
    fn test_interval_sub() {
        let a = IntervalDomain::range(5, 10);
        let b = IntervalDomain::range(1, 3);
        let r = a.sub(&b);
        assert_eq!(r.lo, 2); // 5-3
        assert_eq!(r.hi, 9); // 10-1
    }

    // 32. ConstantDomain display.
    #[test]
    fn test_const_domain_display() {
        assert_eq!(ConstantDomain::Bottom.to_string(), "⊥");
        assert_eq!(ConstantDomain::Top.to_string(), "⊤");
        assert_eq!(ConstantDomain::Const(42).to_string(), "42");
    }

    // 33. AbstractState widen.
    #[test]
    fn test_abstract_state_widen() {
        let mut s1 = AbstractState::<IntervalDomain>::new();
        s1.set("x", IntervalDomain::range(0, 5));
        let mut s2 = AbstractState::<IntervalDomain>::new();
        s2.set("x", IntervalDomain::range(0, 10));
        let w = s1.widen(&s2);
        assert_eq!(w.get("x").hi, IntervalDomain::MAX);
    }

    // 34. TransferFunction phi join.
    #[test]
    fn test_transfer_phi() {
        let mut state = AbstractState::<ConstantDomain>::new();
        state.set("a", ConstantDomain::Const(1));
        state.set("b", ConstantDomain::Const(2));
        let instr = AbstractInstr::Phi {
            dst: "c".into(),
            sources: vec!["a".into(), "b".into()],
        };
        let out = TransferFunction::apply_const(&instr, &state);
        assert_eq!(out.get("c"), ConstantDomain::Top); // 1 ⊔ 2 = ⊤
    }

    // 35. Fixpoint result has entry for each block.
    #[test]
    fn test_fixpoint_all_blocks() {
        let p = make_simple_program();
        let r = Fixpoint::run_const(&p, false);
        for b in &p.blocks {
            assert!(r.pre.contains_key(&b.id), "missing pre for block {}", b.id);
            assert!(
                r.post.contains_key(&b.id),
                "missing post for block {}",
                b.id
            );
        }
    }

    // 36. SignDomain display.
    #[test]
    fn test_sign_display() {
        assert_eq!(SignDomain::Bottom.to_string(), "⊥");
        assert_eq!(SignDomain::Top.to_string(), "⊤");
        assert_eq!(SignDomain::Pos.to_string(), "pos");
        assert_eq!(SignDomain::Neg.to_string(), "neg");
        assert_eq!(SignDomain::Zero.to_string(), "zero");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Randomized soundness properties (layers above StridedInterval).
//
// Technique: a small xorshift PRNG (no external dev-deps) drives thousands of
// random abstract values / programs. Each property asserts "abstract result
// over-approximates every concrete result" against a brute-force reference.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod prop_soundness {
    use super::*;

    use crate::test_prng::Xs;

    fn rand_interval(r: &mut Xs, range: i64) -> IntervalDomain {
        // 1/16 chance of bottom.
        if r.next() % 16 == 0 {
            return IntervalDomain::bottom();
        }
        let a = r.small(range);
        let b = r.small(range);
        IntervalDomain::range(a.min(b), a.max(b))
    }

    fn rand_sign(r: &mut Xs) -> SignDomain {
        match r.next() % 5 {
            0 => SignDomain::Bottom,
            1 => SignDomain::Neg,
            2 => SignDomain::Zero,
            3 => SignDomain::Pos,
            _ => SignDomain::Top,
        }
    }

    fn rand_const(r: &mut Xs, range: i64) -> ConstantDomain {
        match r.next() % 6 {
            0 => ConstantDomain::Bottom,
            1 => ConstantDomain::Top,
            _ => ConstantDomain::Const(r.small(range)),
        }
    }

    // ── Generic lattice laws ───────────────────────────────────────────────

    /// join is an upper bound: a ⊑ a⊔b and b ⊑ a⊔b; and it is commutative.
    fn check_join_lub<D: AbstractDomain>(a: &D, b: &D) {
        let j = a.join(b);
        assert!(a.leq(&j), "join not upper bound of lhs: {a:?} ⊔ {b:?} = {j:?}");
        assert!(b.leq(&j), "join not upper bound of rhs: {a:?} ⊔ {b:?} = {j:?}");
        let j2 = b.join(a);
        assert!(
            j.leq(&j2) && j2.leq(&j),
            "join not commutative: {a:?} ⊔ {b:?}"
        );
    }

    /// meet is a lower bound: a⊓b ⊑ a and a⊓b ⊑ b.
    fn check_meet_glb<D: AbstractDomain>(a: &D, b: &D) {
        let m = a.meet(b);
        assert!(m.leq(a), "meet not lower bound of lhs: {a:?} ⊓ {b:?} = {m:?}");
        assert!(m.leq(b), "meet not lower bound of rhs: {a:?} ⊓ {b:?} = {m:?}");
    }

    #[test]
    fn prop_interval_lattice_laws() {
        let mut r = Xs::new(0xA1B2_C3D4);
        for _ in 0..4000 {
            let a = rand_interval(&mut r, 500);
            let b = rand_interval(&mut r, 500);
            check_join_lub(&a, &b);
            check_meet_glb(&a, &b);
        }
    }

    #[test]
    fn prop_sign_lattice_laws() {
        let mut r = Xs::new(0x1122_3344);
        for _ in 0..4000 {
            let a = rand_sign(&mut r);
            let b = rand_sign(&mut r);
            check_join_lub(&a, &b);
            check_meet_glb(&a, &b);
        }
    }

    #[test]
    fn prop_constant_lattice_laws() {
        let mut r = Xs::new(0x5566_7788);
        for _ in 0..4000 {
            let a = rand_const(&mut r, 50);
            let b = rand_const(&mut r, 50);
            check_join_lub(&a, &b);
            check_meet_glb(&a, &b);
        }
    }

    // ── Widening soundness: the widened result must still over-approximate ──
    // both operands (it is an upper bound), which is what guarantees the
    // fixpoint after widening remains a sound over-approximation.

    #[test]
    fn prop_interval_widen_over_approximates() {
        let mut r = Xs::new(0x9988_7766);
        for _ in 0..4000 {
            let a = rand_interval(&mut r, 1000);
            let b = rand_interval(&mut r, 1000);
            let w = a.widen(&b);
            assert!(a.leq(&w), "widen dropped lhs: {a:?} ▽ {b:?} = {w:?}");
            assert!(b.leq(&w), "widen dropped rhs: {a:?} ▽ {b:?} = {w:?}");
            // Every concrete member of a and b must survive.
            for iv in [&a, &b] {
                if !iv.is_bottom() {
                    for &v in &[iv.lo, iv.hi] {
                        assert!(w.contains(v), "widen dropped concrete {v}: {a:?} ▽ {b:?} = {w:?}");
                    }
                }
            }
        }
    }

    // ── Transfer-function concrete soundness (interval add/sub) ─────────────

    #[test]
    fn prop_interval_transfer_add_sub_concrete() {
        let mut r = Xs::new(0x3141_5926);
        for _ in 0..4000 {
            let a = rand_interval(&mut r, 3000);
            let b = rand_interval(&mut r, 3000);
            if a.is_bottom() || b.is_bottom() {
                assert!(a.add(&b).is_bottom());
                assert!(a.sub(&b).is_bottom());
                continue;
            }
            let sum = a.add(&b);
            let dif = a.sub(&b);
            for &x in &[a.lo, a.hi] {
                for &y in &[b.lo, b.hi] {
                    assert!(sum.contains(x + y), "add missed {x}+{y}: {a:?}+{b:?}={sum:?}");
                    assert!(dif.contains(x - y), "sub missed {x}-{y}: {a:?}-{b:?}={dif:?}");
                }
            }
        }
    }

    // ── SignDomain::add over-approximates the concrete sign ─────────────────

    #[test]
    fn prop_sign_add_over_approximates_concrete() {
        let mut r = Xs::new(0x2718_2818);
        for _ in 0..5000 {
            let x = r.small(1_000_000);
            let y = r.small(1_000_000);
            let Some(s) = x.checked_add(y) else { continue };
            let abs = SignDomain::of(x).add(&SignDomain::of(y));
            let conc = SignDomain::of(s);
            assert!(
                conc.leq(&abs),
                "sign add unsound: of({x})+of({y})={abs} but concrete sign {conc}"
            );
        }
    }

    // ── Fixpoint soundness: the computed solution is a valid post-fixpoint. ─
    // For every edge p→s: post[p] ⊑ pre[s]; and post[b] = transfer*(pre[b]).
    // Built on random DAGs (guaranteed to converge without widening).

    fn rand_dag_program(r: &mut Xs) -> AbsProgram {
        let n = 2 + (r.next() % 5) as usize; // 2..=6 blocks
        let mut p = AbsProgram::new(0);
        for id in 0..n {
            let ninstr = (r.next() % 3) as usize;
            let mut instrs = Vec::new();
            for k in 0..ninstr {
                let dst = format!("v{}_{}", id, k);
                match r.next() % 3 {
                    0 => instrs.push(AbstractInstr::Const { dst, val: r.small(100) }),
                    1 => instrs.push(AbstractInstr::Add {
                        dst,
                        lhs: format!("v{}", r.next() % 4),
                        rhs: format!("v{}", r.next() % 4),
                    }),
                    _ => instrs.push(AbstractInstr::Const { dst: format!("v{}", r.next() % 4), val: r.small(100) }),
                }
            }
            p.add_block(AbsBlock::new(id, instrs));
        }
        // DAG edges: only i→j with i<j.
        for i in 0..n {
            for j in (i + 1)..n {
                if r.next() % 3 == 0 {
                    p.add_edge(i, j);
                }
            }
        }
        p
    }

    #[test]
    fn prop_fixpoint_is_valid_postfixpoint_const() {
        let mut r = Xs::new(0xDEAD_BEEF);
        for _ in 0..1500 {
            let p = rand_dag_program(&mut r);
            let res = Fixpoint::run_const(&p, false);
            // 1. post[pred] ⊑ pre[succ] for every edge.
            for b in &p.blocks {
                let pre_b = res.pre.get(&b.id).unwrap();
                // recompute transfer over pre to confirm post = transfer*(pre).
                let mut st = pre_b.clone();
                for ins in &b.instrs {
                    st = TransferFunction::apply_const(ins, &st);
                }
                let post_b = res.post.get(&b.id).unwrap();
                assert!(
                    st.leq(post_b) && post_b.leq(&st),
                    "post != transfer*(pre) for block {}",
                    b.id
                );
                for &s in &b.successors {
                    let pre_s = res.pre.get(&s).unwrap();
                    assert!(
                        post_b.leq(pre_s),
                        "post[{}] not ⊑ pre[{}] — unsound edge",
                        b.id,
                        s
                    );
                }
            }
        }
    }

    #[test]
    fn prop_fixpoint_sign_valid_postfixpoint() {
        let mut r = Xs::new(0x0BAD_F00D);
        for _ in 0..1500 {
            let p = rand_dag_program(&mut r);
            let res = Fixpoint::run_sign(&p, false);
            for b in &p.blocks {
                let post_b = res.post.get(&b.id).unwrap();
                for &s in &b.successors {
                    let pre_s = res.pre.get(&s).unwrap();
                    assert!(post_b.leq(pre_s), "sign: post[{}] not ⊑ pre[{}]", b.id, s);
                }
            }
        }
    }

    // ── Fixpoint with widening on loops must terminate AND over-approximate.
    #[test]
    fn prop_fixpoint_interval_widening_terminates_and_sound() {
        // A self-looping block: i grows unboundedly; widening must converge
        // and the post-fixpoint edge invariant must hold.
        let mut p = AbsProgram::new(0);
        p.add_block(AbsBlock::new(0, vec![AbstractInstr::Const { dst: "i".into(), val: 0 }]));
        p.add_block(AbsBlock::new(
            1,
            vec![
                AbstractInstr::Phi { dst: "i".into(), sources: vec!["i".into(), "j".into()] },
                AbstractInstr::Add { dst: "j".into(), lhs: "i".into(), rhs: "one".into() },
            ],
        ));
        p.add_block(AbsBlock::new(2, vec![AbstractInstr::Ret]));
        p.add_edge(0, 1);
        p.add_edge(1, 1);
        p.add_edge(1, 2);
        let res = Fixpoint::run_interval(&p, true);
        assert!(res.iterations < 10_000, "widening failed to converge");
        for b in &p.blocks {
            let post_b = res.post.get(&b.id).unwrap();
            for &s in &b.successors {
                let pre_s = res.pre.get(&s).unwrap();
                assert!(post_b.leq(pre_s), "widen: post[{}] not ⊑ pre[{}]", b.id, s);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Randomized property: the fixpoint reached is independent of the worklist's
// initial iteration order (block insertion order) on random DAG programs.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod fixpoint_order_props {
    use super::*;

    use crate::test_prng::xorshift;

    /// Build a random DAG program over variables x/y/z. Edges go only from
    /// lower to higher block id, so the fixpoint converges without widening
    /// and the classic monotone-framework result applies: the least fixpoint
    /// is unique regardless of iteration order.
    fn rand_program(state: &mut u64) -> AbsProgram {
        let vars = ["x", "y", "z"];
        let n = 3 + (xorshift(state) as usize % 4); // 3..=6 blocks
        let mut prog = AbsProgram::new(0);
        for id in 0..n {
            let mut instrs = Vec::new();
            let k = 1 + (xorshift(state) as usize % 3);
            for _ in 0..k {
                let dst = vars[xorshift(state) as usize % 3].to_string();
                match xorshift(state) % 3 {
                    0 => instrs.push(AbstractInstr::Const {
                        dst,
                        val: (xorshift(state) % 100) as i64 - 50,
                    }),
                    1 => instrs.push(AbstractInstr::Add {
                        dst,
                        lhs: vars[xorshift(state) as usize % 3].to_string(),
                        rhs: vars[xorshift(state) as usize % 3].to_string(),
                    }),
                    _ => instrs.push(AbstractInstr::Sub {
                        dst,
                        lhs: vars[xorshift(state) as usize % 3].to_string(),
                        rhs: vars[xorshift(state) as usize % 3].to_string(),
                    }),
                }
            }
            prog.add_block(AbsBlock::new(id, instrs));
        }
        // Random forward edges (DAG).
        for from in 0..n.saturating_sub(1) {
            for to in (from + 1)..n {
                if xorshift(state) % 2 == 0 {
                    prog.add_edge(from, to);
                }
            }
            // Ensure each non-last block has at least one successor so the
            // graph stays connected-ish.
            if prog.block(from).is_some_and(|b| b.successors.is_empty()) {
                prog.add_edge(from, from + 1);
            }
        }
        prog
    }

    /// Same program with the `blocks` vector in a different (reversed) order:
    /// identical CFG, different initial worklist order.
    fn reorder(prog: &AbsProgram) -> AbsProgram {
        let mut p = AbsProgram::new(prog.entry);
        for b in prog.blocks.iter().rev() {
            p.add_block(b.clone());
        }
        p
    }

    fn states_equal<D: AbstractDomain>(
        a: &std::collections::HashMap<usize, AbstractState<D>>,
        b: &std::collections::HashMap<usize, AbstractState<D>>,
    ) -> bool {
        a.len() == b.len()
            && a.iter().all(|(k, va)| {
                b.get(k).is_some_and(|vb| va.leq(vb) && vb.leq(va))
            })
    }

    #[test]
    fn prop_fixpoint_independent_of_iteration_order() {
        let mut state = 0xF1E1D_0D3ced_u64 | 1;
        for i in 0..200 {
            let prog = rand_program(&mut state);
            let rev = reorder(&prog);
            let r1 = Fixpoint::run_interval(&prog, false);
            let r2 = Fixpoint::run_interval(&rev, false);
            assert!(
                states_equal(&r1.pre, &r2.pre) && states_equal(&r1.post, &r2.post),
                "interval fixpoint depends on iteration order (program {i})"
            );
            let c1 = Fixpoint::run_const(&prog, false);
            let c2 = Fixpoint::run_const(&rev, false);
            assert!(
                states_equal(&c1.pre, &c2.pre) && states_equal(&c1.post, &c2.post),
                "const fixpoint depends on iteration order (program {i})"
            );
        }
    }
}

#[cfg(test)]
mod sign_sub_tests {
    use super::*;

    fn st(pairs: &[(&str, SignDomain)]) -> AbstractState<SignDomain> {
        let mut s = AbstractState::new();
        for (k, v) in pairs {
            s.set((*k).to_string(), *v);
        }
        s
    }

    #[test]
    fn sub_computes_sign_of_difference() {
        let s = st(&[("a", SignDomain::Pos), ("b", SignDomain::Neg)]);
        let out = TransferFunction::apply_sign(
            &AbstractInstr::Sub { dst: "d".into(), lhs: "a".into(), rhs: "b".into() },
            &s,
        );
        // pos - neg = pos
        assert_eq!(out.get(&"d".to_string()), SignDomain::Pos);
    }

    /// NEGATIVE test: previously `Sub` hit `_ => {}` and `dst` kept its stale
    /// pre-Sub sign, which a caller could not distinguish from a real result.
    #[test]
    fn sub_never_leaves_stale_sign_on_dst() {
        // d was Pos; pos - pos is unknown, so d must NOT stay Pos.
        let s = st(&[
            ("d", SignDomain::Pos),
            ("a", SignDomain::Pos),
            ("b", SignDomain::Pos),
        ]);
        let out = TransferFunction::apply_sign(
            &AbstractInstr::Sub { dst: "d".into(), lhs: "a".into(), rhs: "b".into() },
            &s,
        );
        assert_eq!(
            out.get(&"d".to_string()),
            SignDomain::Top,
            "Sub must invalidate dst, not retain the stale sign"
        );
    }

    #[test]
    fn run_signs_does_not_report_sub_result_as_positive() {
        let program = AbsProgram {
            blocks: vec![AbsBlock {
                id: 0,
                instrs: vec![
                    AbstractInstr::Const { dst: "x".into(), val: 5 },
                    AbstractInstr::Const { dst: "y".into(), val: 7 },
                    AbstractInstr::Sub { dst: "x".into(), lhs: "x".into(), rhs: "y".into() },
                    AbstractInstr::Ret,
                ],
                successors: vec![],
                predecessors: vec![],
            }],
            entry: 0,
        };
        let (_r, summary) = AbstractInterpreter::run_signs(&program);
        assert!(
            !summary.always_positive.iter().any(|(_, v)| v == "x"),
            "x = 5 - 7 must not be reported always-positive: {:?}",
            summary.always_positive
        );
    }
}
