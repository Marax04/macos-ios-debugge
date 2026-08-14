//! `rustre-symb-engine` Ã¢â‚¬â€ Full symbolic execution engine.
//!
//! Provides:
//! - [`SymbolicExecutor`]: orchestrate symbolic execution from a start address
//! - [`ExecutorConfig`]: policy knobs (depth, state limit, strategy, solver)
//! - [`StateManager`]: worklist management
//! - [`VulnDetector`]: detect vulnerabilities during execution
//! - [`FunctionSummary`]: summarize call effects
//! - [`ReachabilityQuery`]: can a target address be reached?

pub mod concolic_engine;
pub mod exploit_finding;
pub mod loop_summarizer;
pub mod state_manager;
pub mod path_condition_engine;
pub mod path_manager;
pub mod state_merger;
pub mod path_explorer;
pub mod symbolic_store;
pub mod symbolic_memory;
pub mod path_condition;
pub mod symbolic_executor;

use std::collections::{HashMap, HashSet, VecDeque};

use rustre_symb::{SymExpr, SymbolicError, SymbolicState};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Errors Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("state limit reached ({0} states)")]
    StateLimitReached(usize),
    #[error("depth limit reached ({0})")]
    DepthLimitReached(u32),
    #[error("timeout after {0} ms")]
    Timeout(u64),
    #[error("symbolic execution error: {0}")]
    Symbolic(#[from] SymbolicError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Configuration Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Which SMT solver backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum SolverType {
    /// Pure Rust bit-blasting / constant folding (default, always available).
    #[default]
    BitBlasting,
    /// Emit SMT-LIB2 to a subprocess (z3, cvc5 Ã¢â‚¬Â¦).
    SmtLib2,
    /// Full Z3 integration (implemented in `rustre-symb-z3`).
    Z3,
}


/// State-space exploration strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum ExplorationStrategy {
    /// Depth-first search (stack).
    #[default]
    Dfs,
    /// Breadth-first search (queue).
    Bfs,
    /// Random walk (shuffle on each dequeue).
    RandomWalk,
    /// Coverage-guided: prefer states that explore uncovered addresses.
    CoverageGuided,
}


/// Engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorConfig {
    /// Maximum number of live states at any time.
    pub max_states: usize,
    /// Maximum exploration depth (instruction count).
    pub max_depth: u32,
    /// Merge states with identical path conditions when possible.
    pub state_merging: bool,
    /// SMT solver backend.
    pub solver: SolverType,
    /// Wall-clock timeout in milliseconds (0 = unlimited).
    pub timeout_ms: u64,
    /// Exploration strategy.
    pub strategy: ExplorationStrategy,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_states: 1_024,
            max_depth: 512,
            state_merging: false,
            solver: SolverType::BitBlasting,
            timeout_ms: 0,
            strategy: ExplorationStrategy::Dfs,
        }
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ StateManager Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Manages the worklist of active symbolic states.
#[derive(Debug, Default)]
pub struct StateManager {
    worklist: VecDeque<SymbolicState>,
    /// Total states ever enqueued (for statistics).
    total_enqueued: usize,
    /// Pruned state count.
    pruned: usize,
}

impl StateManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a new state onto the worklist.
    pub fn push(&mut self, state: SymbolicState) {
        self.worklist.push_back(state);
        self.total_enqueued += 1;
    }

    /// Pop the next state according to the strategy.
    pub fn pop(&mut self, strategy: ExplorationStrategy) -> Option<SymbolicState> {
        match strategy {
            ExplorationStrategy::Dfs => self.worklist.pop_back(),
            ExplorationStrategy::Bfs
            | ExplorationStrategy::CoverageGuided
            | ExplorationStrategy::RandomWalk => self.worklist.pop_front(),
        }
    }

    /// Remove states whose path condition is trivially unsatisfiable.
    pub fn prune_infeasible(&mut self) {
        let before = self.worklist.len();
        self.worklist.retain(|s| !s.is_path_infeasible());
        self.pruned += before - self.worklist.len();
    }

    /// Current worklist size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.worklist.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.worklist.is_empty()
    }

    #[must_use]
    pub const fn total_enqueued(&self) -> usize {
        self.total_enqueued
    }

    #[must_use]
    pub const fn pruned(&self) -> usize {
        self.pruned
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Symbolic Address Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Represents a memory address that may be symbolic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolicAddress {
    /// Fully concrete address.
    Concrete(u64),
    /// Symbolic expression with a set of possible concrete values.
    Symbolic {
        expr: SymExpr,
        /// Concrete candidates discovered by constraint solving.
        candidates: Vec<u64>,
    },
}

impl SymbolicAddress {
    /// Create from a `SymExpr`: returns `Concrete` if it is a constant.
    #[must_use]
    pub fn from_expr(expr: SymExpr) -> Self {
        expr.as_const_u64().map_or_else(
            || Self::Symbolic { expr, candidates: Vec::new() },
            Self::Concrete,
        )
    }

    /// Whether the address is fully resolved.
    #[must_use]
    pub const fn is_concrete(&self) -> bool {
        matches!(self, Self::Concrete(_))
    }

    /// Return the concrete value, if available.
    #[must_use]
    pub fn concrete_value(&self) -> Option<u64> {
        match self {
            Self::Concrete(v) => Some(*v),
            Self::Symbolic { candidates, .. } if candidates.len() == 1 => {
                Some(candidates[0])
            }
            Self::Symbolic { .. } => None,
        }
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Function Summary Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Summarizes the observable effect of a function as an input Ã¢â€ â€™ output relation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    /// Address of the summarized function.
    pub address: u64,
    /// Name (if known).
    pub name: Option<String>,
    /// Register outputs as expressions over input symbolic variables.
    pub output_registers: HashMap<String, SymExpr>,
    /// Memory effects: written addresses Ã¢â€ â€™ expressions.
    pub memory_writes: Vec<(SymExpr, SymExpr)>,
    /// Return value expression.
    pub return_value: Option<SymExpr>,
    /// Whether the function may not return (e.g. `exit`).
    pub may_not_return: bool,
}

impl FunctionSummary {
    #[must_use]
    pub fn new(address: u64) -> Self {
        Self {
            address,
            name: None,
            output_registers: HashMap::new(),
            memory_writes: Vec::new(),
            return_value: None,
            may_not_return: false,
        }
    }

    /// Apply this summary to a symbolic state.
    pub fn apply(&self, state: &mut SymbolicState) {
        for (reg, expr) in &self.output_registers {
            state.write_register(reg, expr.clone());
        }
        if let Some(rv) = &self.return_value {
            state.write_register("rax", rv.clone());
        }
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Vulnerability Detection Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Vulnerability findings emitted by [`VulnDetector`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnFinding {
    /// A symbolic array index may exceed the array's bound.
    BufferOverflow {
        address: u64,
        index_expr: SymExpr,
        bound: u64,
    },
    /// A symbolic pointer may be null.
    NullDeref { address: u64, ptr_expr: SymExpr },
    /// An arithmetic result may overflow the bitvector width.
    IntegerOverflow {
        address: u64,
        expr: SymExpr,
        width: u32,
    },
    /// Access to symbolic memory that has been freed.
    UseAfterFree { address: u64, ptr_expr: SymExpr },
    /// A symbolic expression reaches a printf-family format argument.
    FormatStringBug { address: u64, format_expr: SymExpr },
}

/// Checks symbolic states for potential vulnerabilities.
#[derive(Debug, Default)]
pub struct VulnDetector {
    findings: Vec<VulnFinding>,
    /// Set of addresses that have been freed (as concrete values).
    freed_addresses: HashSet<u64>,
}

impl VulnDetector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check a symbolic pointer for potential null dereference.
    ///
    /// `path_constraints` is the accumulated path condition for the current
    /// state.  Before flagging a symbolic pointer, this method performs a
    /// lightweight syntactic check: if any constraint in the path condition
    /// is `BoolNot(Eq(ptr, 0))` (i.e. `ptr != 0`), the pointer is provably
    /// non-null on this path and the finding is suppressed.
    pub fn check_null_deref(
        &mut self,
        pc: u64,
        ptr: &SymExpr,
        path_constraints: &[SymExpr],
    ) {
        match ptr {
            SymExpr::ConstBv { val: 0, .. } => {
                self.findings.push(VulnFinding::NullDeref {
                    address: pc,
                    ptr_expr: ptr.clone(),
                });
            }
            SymExpr::ConstBv { .. } => {
                // Concrete non-null Ã¢â‚¬â€ safe.
            }
            _ => {
                // Symbolic Ã¢â‚¬â€ flag unless the path constraints exclude zero.
                if !Self::constraints_exclude_zero(ptr, path_constraints) {
                    self.findings.push(VulnFinding::NullDeref {
                        address: pc,
                        ptr_expr: ptr.clone(),
                    });
                }
            }
        }
    }

    /// Syntactically check whether `path_constraints` contains a constraint
    /// that proves `ptr != 0` on this path.
    ///
    /// Recognises the pattern `BoolNot(Eq(ptr, ConstBv(0)))` which is the
    /// canonical form emitted when a branch on `ptr != 0` is taken.
    fn constraints_exclude_zero(ptr: &SymExpr, constraints: &[SymExpr]) -> bool {
        for c in constraints {
            // Pattern: BoolNot(Eq(ptr, 0)) Ã¢â‚¬â€ the taken branch of ptr != 0.
            if let SymExpr::BoolNot(inner) = c && let SymExpr::Eq(lhs, rhs) = inner.as_ref() {
                let zero = matches!(rhs.as_ref(), SymExpr::ConstBv { val: 0, .. })
                    || matches!(lhs.as_ref(), SymExpr::ConstBv { val: 0, .. });
                let matches_ptr = lhs.as_ref() == ptr || rhs.as_ref() == ptr;
                if zero && matches_ptr {
                    return true;
                }
            }
        }
        false
    }

    /// Check an array access: `index` into an array of `bound` elements.
    pub fn check_buffer_overflow(&mut self, pc: u64, index: &SymExpr, bound: u64) {
        match index {
            SymExpr::ConstBv { val, .. } => {
                if *val >= bound {
                    self.findings.push(VulnFinding::BufferOverflow {
                        address: pc,
                        index_expr: index.clone(),
                        bound,
                    });
                }
            }
            _ => {
                // Symbolic index Ã¢â‚¬â€ conservative flag.
                self.findings.push(VulnFinding::BufferOverflow {
                    address: pc,
                    index_expr: index.clone(),
                    bound,
                });
            }
        }
    }

    /// Check for integer overflow after a bitvector arithmetic operation.
    ///
    /// `result` is the raw (unwrapped) expression; if it is a constant
    /// that exceeds `width` bits this is flagged.
    pub fn check_integer_overflow(&mut self, pc: u64, result: &SymExpr, width: u32) {
        if let SymExpr::ConstBv { val, width: rw } = result
            && *rw > width {
                let mask = if width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                };
                if *val > mask {
                    self.findings.push(VulnFinding::IntegerOverflow {
                        address: pc,
                        expr: result.clone(),
                        width,
                    });
                }
            }
    }

    /// Register that a pointer has been freed.
    pub fn register_free(&mut self, addr: u64) {
        self.freed_addresses.insert(addr);
    }

    /// Check whether a concrete pointer access targets freed memory.
    pub fn check_use_after_free(&mut self, pc: u64, ptr: &SymExpr) {
        if let SymExpr::ConstBv { val, .. } = ptr
            && self.freed_addresses.contains(val) {
                self.findings.push(VulnFinding::UseAfterFree {
                    address: pc,
                    ptr_expr: ptr.clone(),
                });
            }
    }

    /// Check whether a format argument to a printf-like function is symbolic.
    pub fn check_format_string(&mut self, pc: u64, fmt_arg: &SymExpr) {
        if !fmt_arg.is_const() {
            self.findings.push(VulnFinding::FormatStringBug {
                address: pc,
                format_expr: fmt_arg.clone(),
            });
        }
    }

    /// Drain all accumulated findings.
    pub fn drain_findings(&mut self) -> Vec<VulnFinding> {
        std::mem::take(&mut self.findings)
    }

    /// Borrow all accumulated findings.
    #[must_use]
    pub fn findings(&self) -> &[VulnFinding] {
        &self.findings
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Reachability Query Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Query: is `target_address` reachable from the start of execution?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityQuery {
    pub target_address: u64,
}

/// Answer to a [`ReachabilityQuery`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityResult {
    pub reachable: bool,
    /// Input constraints that make the target reachable.
    pub witness_constraints: Vec<SymExpr>,
    /// The symbolic state at the target, if found.
    pub witness_state: Option<SymbolicState>,
}

impl ReachabilityResult {
    #[must_use]
    pub fn reachable(state: SymbolicState) -> Self {
        let constraints = state.all_constraints();
        Self {
            reachable: true,
            witness_constraints: constraints,
            witness_state: Some(state),
        }
    }

    #[must_use]
    pub const fn unreachable() -> Self {
        Self {
            reachable: false,
            witness_constraints: vec![],
            witness_state: None,
        }
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ SymbolicExecutor Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Orchestrates symbolic execution of a binary from a given address.
///
/// The executor works on the abstract `SymbolicState` level.  Concrete
/// instruction decoding and stepping is delegated to a user-supplied
/// closure / implementor of the step callback, keeping the engine
/// architecture-independent.
#[derive(Debug)]
pub struct SymbolicExecutor {
    pub config: ExecutorConfig,
    pub state_manager: StateManager,
    pub vuln_detector: VulnDetector,
    /// Summaries for known functions (keyed by address).
    pub function_summaries: HashMap<u64, FunctionSummary>,
    /// Addresses visited across all paths.
    pub visited_addresses: HashSet<u64>,
}

impl SymbolicExecutor {
    #[must_use]
    pub fn new(config: ExecutorConfig) -> Self {
        Self {
            config,
            state_manager: StateManager::new(),
            vuln_detector: VulnDetector::new(),
            function_summaries: HashMap::new(),
            visited_addresses: HashSet::new(),
        }
    }

    #[must_use]
    pub fn with_default_config() -> Self {
        Self::new(ExecutorConfig::default())
    }

    /// Seed execution with an initial state at `start_address`.
    pub fn seed(&mut self, start_address: u64) {
        let mut state = SymbolicState::new();
        state.pc = start_address;
        self.state_manager.push(state);
    }

    /// Register a function summary.
    pub fn register_summary(&mut self, summary: FunctionSummary) {
        self.function_summaries.insert(summary.address, summary);
    }

    /// Run one symbolic step using a caller-supplied stepper.
    ///
    /// The `stepper` receives the current state and returns successor states.
    /// Returns `Ok(true)` if more states remain, `Ok(false)` if exhausted.
    ///
    /// # Errors
    /// Returns [`EngineError`] if the state or depth limit is exceeded.
    pub fn step_once<F>(&mut self, stepper: &mut F) -> Result<bool, EngineError>
    where
        F: FnMut(&SymbolicState) -> Result<Vec<SymbolicState>, SymbolicError>,
    {
        let strategy = self.config.strategy;
        let Some(state) = self.state_manager.pop(strategy) else {
            return Ok(false);
        };

        if state.depth >= self.config.max_depth {
            return Err(EngineError::DepthLimitReached(state.depth));
        }

        self.visited_addresses.insert(state.pc);

        let successors = stepper(&state)?;
        for succ in successors {
            if self.state_manager.len() >= self.config.max_states {
                return Err(EngineError::StateLimitReached(self.config.max_states));
            }
            if !succ.is_path_infeasible() {
                self.state_manager.push(succ);
            }
        }

        Ok(!self.state_manager.is_empty())
    }

    /// Run to exhaustion (or until a limit is hit) using the given stepper.
    ///
    /// # Errors
    /// Propagates stepper errors.
    pub fn run<F>(&mut self, stepper: &mut F) -> Result<(), EngineError>
    where
        F: FnMut(&SymbolicState) -> Result<Vec<SymbolicState>, SymbolicError>,
    {
        loop {
            match self.step_once(stepper) {
                Ok(true) => {}
                Ok(false) => return Ok(()),
                Err(EngineError::DepthLimitReached(_)) => {
                    // Continue from next state in worklist.
                    if self.state_manager.is_empty() {
                        return Ok(());
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Check whether `query.target_address` is reachable.
    ///
    /// Accepts a stepper to advance execution; returns `reachable` as soon as
    /// any state reaches `target_address`.
    ///
    /// # Errors
    /// Returns [`EngineError`] if a limit is exceeded or the stepper fails.
    pub fn check_reachability<F>(
        &mut self,
        query: &ReachabilityQuery,
        stepper: &mut F,
    ) -> Result<ReachabilityResult, EngineError>
    where
        F: FnMut(&SymbolicState) -> Result<Vec<SymbolicState>, SymbolicError>,
    {
        let target = query.target_address;
        loop {
            let strategy = self.config.strategy;
            let Some(state) = self.state_manager.pop(strategy) else {
                return Ok(ReachabilityResult::unreachable());
            };
            if state.pc == target {
                return Ok(ReachabilityResult::reachable(state));
            }
            if state.depth >= self.config.max_depth {
                continue;
            }
            self.visited_addresses.insert(state.pc);
            let successors = stepper(&state)?;
            for succ in successors {
                if self.state_manager.len() >= self.config.max_states {
                    return Err(EngineError::StateLimitReached(self.config.max_states));
                }
                if !succ.is_path_infeasible() {
                    self.state_manager.push(succ);
                }
            }
        }
    }

    /// Apply a known function summary to a state (inlining the call).
    pub fn apply_summary(&self, addr: u64, state: &mut SymbolicState) -> bool {
        self.function_summaries.get(&addr).inspect(|s| s.apply(state)).is_some()
    }

    /// Enumerate possible concrete values for a symbolic address (bounded).
    ///
    /// In a real engine this would invoke the SMT solver.  Here we use a
    /// simple heuristic: if the expression is a constant, return it; otherwise
    /// return a conservative empty list (no candidates).
    #[must_use]
    pub fn concretize_address(&self, addr_expr: &SymExpr) -> Vec<u64> {
        match addr_expr {
            SymExpr::ConstBv { val, .. } => vec![*val],
            SymExpr::Add(l, r) => {
                // Try constant-fold one level.
                if let (Some(lv), Some(rv)) = (l.as_const_u64(), r.as_const_u64()) {
                    vec![lv.wrapping_add(rv)]
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    /// Statistics summary.
    #[must_use]
    pub fn stats(&self) -> ExecutorStats {
        ExecutorStats {
            live_states: self.state_manager.len(),
            total_enqueued: self.state_manager.total_enqueued(),
            pruned_states: self.state_manager.pruned(),
            visited_addresses: self.visited_addresses.len(),
            vuln_count: self.vuln_detector.findings().len(),
        }
    }
}

/// Snapshot of executor statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorStats {
    pub live_states: usize,
    pub total_enqueued: usize,
    pub pruned_states: usize,
    pub visited_addresses: usize,
    pub vuln_count: usize,
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Spec-required types Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

use rustre_symb::{SpecSymExpr, SymConstraint, SymState as RustreSymState, SymWidth};

/// Reason why symbolic execution halted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaltReason {
    Error(String),
    MaxSteps,
    ExplicitHalt,
    Unreachable,
}

impl std::fmt::Display for HaltReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error(s) => write!(f, "Error({s})"),
            Self::MaxSteps => write!(f, "MaxSteps"),
            Self::ExplicitHalt => write!(f, "ExplicitHalt"),
            Self::Unreachable => write!(f, "Unreachable"),
        }
    }
}

/// A single execution step result.
#[derive(Debug, Clone)]
pub enum ExecStep {
    Continue,
    Branch {
        true_state: Box<RustreSymState>,
        false_state: Box<RustreSymState>,
    },
    Halt(HaltReason),
}

impl std::fmt::Display for ExecStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Continue => write!(f, "Continue"),
            Self::Branch { .. } => write!(f, "Branch"),
            Self::Halt(r) => write!(f, "Halt({r})"),
        }
    }
}

/// A symbolic instruction.
#[derive(Debug, Clone)]
pub struct SymInstruction {
    pub address: u64,
    pub op: SymOp,
}

/// Operations a symbolic instruction can perform.
#[derive(Debug, Clone)]
pub enum SymOp {
    Assign {
        dst: String,
        src: String,
    },
    Load {
        dst: String,
        addr: u64,
    },
    Store {
        addr: u64,
        src: String,
    },
    Add {
        dst: String,
        lhs: String,
        rhs: String,
    },
    BranchCond {
        cond: String,
        true_addr: u64,
        false_addr: u64,
    },
    Call(u64),
    Ret,
    Nop,
}

impl std::fmt::Display for SymOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Assign { dst, src } => write!(f, "{dst} = {src}"),
            Self::Load { dst, addr } => write!(f, "{dst} = mem[{addr:#x}]"),
            Self::Store { addr, src } => write!(f, "mem[{addr:#x}] = {src}"),
            Self::Add { dst, lhs, rhs } => write!(f, "{dst} = {lhs} + {rhs}"),
            Self::BranchCond {
                cond,
                true_addr,
                false_addr,
            } => write!(f, "branch {cond} ? {true_addr:#x} : {false_addr:#x}"),
            Self::Call(addr) => write!(f, "call {addr:#x}"),
            Self::Ret => write!(f, "ret"),
            Self::Nop => write!(f, "nop"),
        }
    }
}

/// Result from exploring a single path.
#[derive(Debug, Clone)]
pub struct PathResult {
    pub final_state: RustreSymState,
    pub path: Vec<u64>,
    pub steps: usize,
    pub halt: HaltReason,
}

impl PathResult {
    /// Return `true` if the path completed without error.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.halt, HaltReason::ExplicitHalt | HaltReason::MaxSteps)
    }
}

/// Configuration for the symbolic engine.
#[derive(Debug, Clone)]
pub struct ExecConfig {
    pub max_steps: usize,
    pub max_paths: usize,
    pub explore_both_branches: bool,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            max_steps: 1000,
            max_paths: 64,
            explore_both_branches: true,
        }
    }
}

/// Lightweight symbolic engine.
pub struct SymEngine {
    pub config: ExecConfig,
}

impl SymEngine {
    /// Create a new engine with the given configuration.
    #[must_use]
    pub const fn new(config: ExecConfig) -> Self {
        Self { config }
    }

    /// Execute a program from an initial state, returning all path results.
    #[must_use]
    pub fn execute(&self, program: &[SymInstruction], initial: RustreSymState) -> Vec<PathResult> {
        let mut explorer = PathExplorer::new(Self::new(self.config.clone()));
        explorer.push_state(initial, vec![]);
        explorer.explore(program)
    }

    /// Step a single instruction and return an `ExecStep`.
    pub fn step(&self, instr: &SymInstruction, state: &mut RustreSymState) -> ExecStep {
        match &instr.op {
            SymOp::Nop | SymOp::Call(_) => ExecStep::Continue,
            SymOp::Ret => ExecStep::Halt(HaltReason::ExplicitHalt),
            SymOp::Assign { dst, src } => {
                if let Some(val) = state.get_var(src).cloned() {
                    state.set_var(dst.clone(), val);
                } else {
                    state.set_var(
                        dst.clone(),
                        SpecSymExpr::Var {
                            name: src.clone(),
                            width: SymWidth::W64,
                        },
                    );
                }
                ExecStep::Continue
            }
            SymOp::Load { dst, addr } => {
                let val = state
                    .load_mem(*addr)
                    .cloned()
                    .unwrap_or_else(|| SpecSymExpr::Var {
                        name: format!("mem_{addr:#x}"),
                        width: SymWidth::W64,
                    });
                state.set_var(dst.clone(), val);
                ExecStep::Continue
            }
            SymOp::Store { addr, src } => {
                if let Some(val) = state.get_var(src).cloned() {
                    state.store_mem(*addr, val);
                }
                ExecStep::Continue
            }
            SymOp::Add { dst, lhs, rhs } => {
                let lv = state
                    .get_var(lhs)
                    .cloned()
                    .unwrap_or_else(|| SpecSymExpr::Var {
                        name: lhs.clone(),
                        width: SymWidth::W64,
                    });
                let rv = state
                    .get_var(rhs)
                    .cloned()
                    .unwrap_or_else(|| SpecSymExpr::Var {
                        name: rhs.clone(),
                        width: SymWidth::W64,
                    });
                state.set_var(dst.clone(), SpecSymExpr::Add(Box::new(lv), Box::new(rv)));
                ExecStep::Continue
            }
            SymOp::BranchCond {
                cond,
                true_addr,
                false_addr,
            } => {
                let cond_val = state.get_var(cond).cloned();
                if let Some(SpecSymExpr::Const { val, .. }) = cond_val {
                    // Concrete branch: add a constraint recording which arm was
                    // taken, so path conditions remain accurate. The PC is
                    // managed by the sequential PathExplorer; we record the
                    // taken/not-taken direction via a definite constraint.
                    let taken_addr = if val != 0 { *true_addr } else { *false_addr };
                    let cond_expr = SpecSymExpr::Var {
                        name: cond.clone(),
                        width: SymWidth::W8,
                    };
                    let constraint = if val != 0 {
                        SymConstraint::assert(cond_expr)
                    } else {
                        SymConstraint::deny(cond_expr)
                    };
                    // Push the taken state; the other direction is infeasible.
                    let mut taken_state = state.clone_state();
                    taken_state.add_constraint(constraint);
                    // Store the resolved target address as a special var so
                    // callers can inspect which branch was resolved.
                    taken_state.set_var(
                        "__branch_target".to_string(),
                        SpecSymExpr::Const { val: taken_addr, width: SymWidth::W64 },
                    );
                    ExecStep::Branch {
                        true_state: Box::new(taken_state),
                        false_state: Box::new(state.clone_state()),
                    }
                } else if self.config.explore_both_branches {
                    let mut true_state = state.clone_state();
                    let mut false_state = state.clone_state();
                    let cond_expr = SpecSymExpr::Var {
                        name: cond.clone(),
                        width: SymWidth::W8,
                    };
                    true_state.add_constraint(SymConstraint::assert(cond_expr.clone()));
                    false_state.add_constraint(SymConstraint::deny(cond_expr));
                    ExecStep::Branch {
                        true_state: Box::new(true_state),
                        false_state: Box::new(false_state),
                    }
                } else {
                    ExecStep::Continue
                }
            }
        }
    }
}

/// Worklist-based path explorer.
pub struct PathExplorer {
    pub engine: SymEngine,
    pub worklist: Vec<(RustreSymState, Vec<u64>)>,
}

impl PathExplorer {
    /// Create a new explorer.
    #[must_use]
    pub const fn new(engine: SymEngine) -> Self {
        Self {
            engine,
            worklist: Vec::new(),
        }
    }

    /// Push a new state onto the worklist.
    pub fn push_state(&mut self, s: RustreSymState, path: Vec<u64>) {
        self.worklist.push((s, path));
    }

    /// Pop the next state from the worklist.
    #[must_use]
    pub fn pop_next(&mut self) -> Option<(RustreSymState, Vec<u64>)> {
        self.worklist.pop()
    }

    /// Explore all reachable paths through `program`.
    #[must_use]
    pub fn explore(&mut self, program: &[SymInstruction]) -> Vec<PathResult> {
        let mut results = Vec::new();
        while let Some((mut state, mut path)) = self.pop_next() {
            if results.len() >= self.engine.config.max_paths {
                break;
            }
            let mut steps = 0;
            let mut halt = HaltReason::MaxSteps;
            let mut branched = false;
            for instr in program {
                if steps >= self.engine.config.max_steps {
                    break;
                }
                path.push(instr.address);
                let step = self.engine.step(instr, &mut state);
                steps += 1;
                match step {
                    ExecStep::Continue => {}
                    ExecStep::Halt(reason) => {
                        halt = reason;
                        break;
                    }
                    ExecStep::Branch {
                        true_state,
                        false_state,
                    } => {
                        self.worklist.push((*false_state, path.clone()));
                        state = *true_state;
                        branched = true;
                    }
                }
            }
            if !branched {
                halt = HaltReason::ExplicitHalt;
            }
            results.push(PathResult {
                final_state: state,
                path,
                steps,
                halt,
            });
        }
        results
    }
}

/// Engine errors (spec: `EngineError` — additional variants beyond existing).
/// The existing `EngineError` is kept; these spec-required variants are in `SpecEngineError`.
#[derive(Debug, thiserror::Error)]
pub enum SpecEngineError {
    #[error("step limit exceeded: {0}")]
    StepLimitExceeded(usize),
    #[error("path limit exceeded: {0}")]
    PathLimitExceeded(usize),
    #[error("invalid program: {0}")]
    InvalidProgram(String),
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ SymbolicInterpreter Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// A minimal lifted instruction suitable for symbolic interpretation.
///
/// When `rustre-il-lift` is not a direct dependency this type stands in as the
/// instruction currency for [`SymbolicInterpreter`].  Fields mirror those of
/// `rustre_il_lift::LiftedInstr` so real lifted instructions can be trivially
/// converted.
#[derive(Debug, Clone)]
pub struct LiftedInstr {
    /// Address of the original instruction.
    pub address: u64,
    /// Original mnemonic string.
    pub original_mnemonic: String,
    /// Textual IR representation (used for display / diagnostics).
    pub ir_text: String,
}

impl LiftedInstr {
    /// Construct a minimal `LiftedInstr` for testing / manual construction.
    #[must_use]
    pub fn new(address: u64, mnemonic: impl Into<String>) -> Self {
        let mnemonic = mnemonic.into();
        Self {
            address,
            ir_text: mnemonic.clone(),
            original_mnemonic: mnemonic,
        }
    }
}

/// Symbolic state used by [`SymbolicInterpreter`].
///
/// Distinct from `rustre_symb::SymbolicState` (which tracks the full path
/// condition for the executor engine); this struct is a lightweight map-based
/// view used during block-level symbolic interpretation.
#[derive(Debug, Clone, Default)]
pub struct SymbolicInterpreterState {
    /// Register file: register name Ã¢â€ â€™ symbolic expression.
    pub regs: HashMap<String, SymExpr>,
    /// Flat memory model: concrete address Ã¢â€ â€™ symbolic byte value.
    pub memory: HashMap<u64, SymExpr>,
}

impl SymbolicInterpreterState {
    /// Create an empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a register, returning a fresh symbolic variable if not defined.
    #[must_use]
    pub fn read_reg(&self, name: &str) -> SymExpr {
        self.regs
            .get(name)
            .cloned()
            .unwrap_or_else(|| SymExpr::Var {
                name: name.to_string(),
                ty: rustre_symb::SymType::BitVec(64),
            })
    }

    /// Write a register.
    pub fn write_reg(&mut self, name: impl Into<String>, val: SymExpr) {
        self.regs.insert(name.into(), val);
    }

    /// Load a symbolic value from memory at `addr`.
    #[must_use]
    pub fn load(&self, addr: u64) -> SymExpr {
        self.memory
            .get(&addr)
            .cloned()
            .unwrap_or_else(|| SymExpr::Load {
                addr: Box::new(SymExpr::ConstBv {
                    val: addr,
                    width: 64,
                }),
                size: 8,
            })
    }

    /// Store a symbolic value into memory at `addr`.
    pub fn store(&mut self, addr: u64, val: SymExpr) {
        self.memory.insert(addr, val);
    }
}

/// A branch constraint produced during symbolic execution of a block.
#[derive(Debug, Clone)]
pub struct PathConstraint {
    /// The condition expression for this branch.
    pub condition: SymExpr,
    /// Whether this path corresponds to the branch being taken.
    pub taken: bool,
}

impl PathConstraint {
    #[must_use]
    pub const fn new(condition: SymExpr, taken: bool) -> Self {
        Self { condition, taken }
    }
}

/// Executes lifted IL blocks symbolically, returning path constraints.
#[derive(Debug, Default)]
pub struct SymbolicInterpreter {
    /// Counter for generating fresh symbolic variable names.
    sym_counter: u64,
}

impl SymbolicInterpreter {
    /// Create a new interpreter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Symbolically execute a block of lifted instructions, updating `state`
    /// and returning any [`PathConstraint`]s generated by conditional branches.
    ///
    /// The interpreter performs a lightweight, textual-IR-driven pass:
    /// - Instructions whose `ir_text` contains `"branch"` or `"jmp"` generate
    ///   a pair of path constraints (taken / not-taken).
    /// - Instructions containing `":= "` are treated as register assignments
    ///   and stored in `state.regs` as fresh symbolic expressions.
    /// - Memory store patterns (`"mem["`) are forwarded to `state.memory`.
    pub fn execute_block(
        &mut self,
        instrs: &[LiftedInstr],
        state: &mut SymbolicInterpreterState,
    ) -> Vec<PathConstraint> {
        let mut constraints = Vec::new();
        for instr in instrs {
            let ir = instr.ir_text.as_str();
            if ir.contains("branch")
                || ir.contains("jmp")
                || ir.contains("je ")
                || ir.contains("jne")
                || ir.contains("jz ")
                || ir.contains("jnz")
            {
                // Generate a fresh symbolic condition for the branch.
                let cond = self.fresh_sym(1);
                constraints.push(PathConstraint::new(cond.clone(), true));
                constraints.push(PathConstraint::new(SymExpr::BoolNot(Box::new(cond)), false));
            } else if let Some(pos) = ir.find(":= ") {
                // Simple assignment: lhs := rhs
                let lhs = ir[..pos].trim().to_string();
                let rhs_text = ir[pos + 3..].trim();
                let val = rhs_text.parse::<u64>().map_or_else(|_| self.fresh_sym_named(&lhs), |n| SymExpr::ConstBv { val: n, width: 64 });
                state.write_reg(lhs, val);
            } else if ir.contains("mem[") {
                // Symbolic memory effect Ã¢â‚¬â€ mark the instruction address as written.
                let sym = self.fresh_sym(64);
                state.store(instr.address, sym);
            }
        }
        constraints
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Internal helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    fn fresh_sym(&mut self, width: u32) -> SymExpr {
        let id = self.sym_counter;
        self.sym_counter += 1;
        SymExpr::Var {
            name: format!("sym_{id}"),
            ty: rustre_symb::SymType::BitVec(width),
        }
    }

    fn fresh_sym_named(&mut self, base: &str) -> SymExpr {
        let id = self.sym_counter;
        self.sym_counter += 1;
        SymExpr::Var {
            name: format!("{base}_{id}"),
            ty: rustre_symb::SymType::BitVec(64),
        }
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ ConstraintSolver Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Abstract interface for satisfiability checking of path constraints.
pub trait ConstraintSolver {
    /// Return `true` if the conjunction of all constraints is satisfiable (or
    /// unknown / conservatively assumed satisfiable).
    fn is_satisfiable(&self, constraints: &[PathConstraint]) -> bool;
}

/// Concrete evaluator that always returns `true` (satisfiable / unknown).
///
/// Used as a safe, always-available fallback for testing pipelines that do not
/// require a real SMT backend.
#[derive(Debug, Default)]
pub struct ConcreteEvaluator;

impl ConcreteEvaluator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ConstraintSolver for ConcreteEvaluator {
    fn is_satisfiable(&self, _constraints: &[PathConstraint]) -> bool {
        true
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ SymbolicSummary Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// A symbolic input parameter to a function.
#[derive(Debug, Clone)]
pub struct SymbolicInput {
    /// Register or argument name that carries this input.
    pub name: String,
    /// Symbolic expression representing the unconstrained input value.
    pub expr: SymExpr,
}

/// A symbolic output value produced by a function.
#[derive(Debug, Clone)]
pub struct SymbolicOutput {
    /// Register or memory location that holds this output.
    pub location: String,
    /// Symbolic expression for the output value (may reference inputs).
    pub expr: SymExpr,
}

/// A side-effect produced by a function during symbolic execution.
#[derive(Debug, Clone)]
pub enum SymbolicEffect {
    /// A memory write occurred at a (possibly symbolic) address.
    MemoryWrite { addr: u64, value: SymExpr },
    /// A system call was made.
    Syscall { number: SymExpr },
    /// A branch was taken under the given condition.
    Branch { condition: SymExpr, taken: bool },
}

/// Summarizes a function's symbolic behavior: its inputs, outputs, and
/// observable side-effects as seen by a symbolic pass over its instructions.
#[derive(Debug, Clone, Default)]
pub struct SymbolicSummary {
    /// Symbolic input parameters (registers / arguments read before any write).
    pub inputs: Vec<SymbolicInput>,
    /// Symbolic output values (registers written during execution).
    pub outputs: Vec<SymbolicOutput>,
    /// Side-effects observed during symbolic execution.
    pub side_effects: Vec<SymbolicEffect>,
}

impl SymbolicSummary {
    /// Generate a symbolic summary by running a [`SymbolicInterpreter`] over
    /// the provided instructions and inspecting the resulting state.
    #[must_use]
    pub fn generate(func_name: &str, instrs: &[LiftedInstr]) -> Self {
        let mut interp = SymbolicInterpreter::new();
        let mut state = SymbolicInterpreterState::new();
        let constraints = interp.execute_block(instrs, &mut state);

        // Determine inputs: standard calling-convention registers that were
        // read as fresh symbolic variables (i.e. they appear as Var in the
        // final register map).
        let input_regs = [
            "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r0", "r1", "r2", "r3", "a0", "a1", "a2", "a3",
        ];
        let inputs: Vec<SymbolicInput> = input_regs
            .iter()
            .filter(|&&r| {
                // A register is considered an input if the current value is
                // still a fresh Var (i.e. we never wrote a concrete definition).
                state
                    .regs
                    .get(r)
                    .is_some_and(|e| matches!(e, SymExpr::Var { .. }))
            })
            .map(|&r| SymbolicInput {
                name: r.to_string(),
                expr: state.read_reg(r),
            })
            .collect();

        // Outputs: all registers that were written.
        let outputs: Vec<SymbolicOutput> = state
            .regs
            .iter()
            .map(|(name, expr)| SymbolicOutput {
                location: name.clone(),
                expr: expr.clone(),
            })
            .collect();

        // Side-effects: memory writes observed in state + branch constraints.
        let mut side_effects: Vec<SymbolicEffect> = state
            .memory
            .iter()
            .map(|(&addr, val)| SymbolicEffect::MemoryWrite {
                addr,
                value: val.clone(),
            })
            .collect();

        for pc in constraints {
            side_effects.push(SymbolicEffect::Branch {
                condition: pc.condition,
                taken: pc.taken,
            });
        }

        // Add a Syscall effect if any instruction looks like a syscall.
        for instr in instrs {
            let ir = instr.ir_text.as_str();
            if ir.contains("syscall") || ir.contains("int 0x80") || ir.contains("svc") {
                side_effects.push(SymbolicEffect::Syscall {
                    number: SymExpr::Var {
                        name: format!("{func_name}_syscall_nr"),
                        ty: rustre_symb::SymType::BitVec(64),
                    },
                });
            }
        }

        Self {
            inputs,
            outputs,
            side_effects,
        }
    }

    /// Number of observed side-effects.
    #[must_use]
    pub const fn side_effect_count(&self) -> usize {
        self.side_effects.len()
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Tests Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_symb::{SymExpr, SymType};

    fn bv(val: u64, w: u32) -> SymExpr {
        SymExpr::ConstBv { val, width: w }
    }
    fn var(n: &str) -> SymExpr {
        SymExpr::var(n, SymType::BitVec(64))
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ ExecutorConfig Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_default_config() {
        let cfg = ExecutorConfig::default();
        assert_eq!(cfg.max_states, 1_024);
        assert_eq!(cfg.max_depth, 512);
        assert_eq!(cfg.solver, SolverType::BitBlasting);
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ StateManager Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_state_manager_dfs_lifo() {
        let mut sm = StateManager::new();
        let mut s1 = SymbolicState::new();
        s1.pc = 1;
        let mut s2 = SymbolicState::new();
        s2.pc = 2;
        sm.push(s1);
        sm.push(s2);
        let popped = sm.pop(ExplorationStrategy::Dfs).unwrap();
        assert_eq!(popped.pc, 2); // LIFO
    }

    #[test]
    fn test_state_manager_bfs_fifo() {
        let mut sm = StateManager::new();
        let mut s1 = SymbolicState::new();
        s1.pc = 1;
        let mut s2 = SymbolicState::new();
        s2.pc = 2;
        sm.push(s1);
        sm.push(s2);
        let popped = sm.pop(ExplorationStrategy::Bfs).unwrap();
        assert_eq!(popped.pc, 1); // FIFO
    }

    #[test]
    fn test_state_manager_prune_infeasible() {
        let mut sm = StateManager::new();
        let mut s1 = SymbolicState::new();
        s1.pc = 1;
        let mut s2 = SymbolicState::new();
        s2.add_path_condition(SymExpr::ConstBool(false)); // infeasible
        sm.push(s1);
        sm.push(s2);
        sm.prune_infeasible();
        assert_eq!(sm.len(), 1);
        assert_eq!(sm.pruned(), 1);
    }

    #[test]
    fn test_state_manager_total_enqueued() {
        let mut sm = StateManager::new();
        for i in 0..5u64 {
            let mut s = SymbolicState::new();
            s.pc = i;
            sm.push(s);
        }
        assert_eq!(sm.total_enqueued(), 5);
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ SymbolicAddress Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_symbolic_address_from_const() {
        let a = SymbolicAddress::from_expr(bv(0x1000, 64));
        assert!(a.is_concrete());
        assert_eq!(a.concrete_value(), Some(0x1000));
    }

    #[test]
    fn test_symbolic_address_from_var() {
        let a = SymbolicAddress::from_expr(var("rax"));
        assert!(!a.is_concrete());
        assert_eq!(a.concrete_value(), None);
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ FunctionSummary Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_function_summary_apply() {
        let mut summary = FunctionSummary::new(0xdead_beef);
        summary.return_value = Some(bv(42, 64));
        summary.output_registers.insert("rcx".into(), bv(7, 64));

        let mut state = SymbolicState::new();
        summary.apply(&mut state);
        assert_eq!(state.read_register("rax"), bv(42, 64));
        assert_eq!(state.read_register("rcx"), bv(7, 64));
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ VulnDetector Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_vuln_null_deref_concrete_null() {
        let mut vd = VulnDetector::new();
        vd.check_null_deref(0x1000, &bv(0, 64), &[]);
        let findings = vd.drain_findings();
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            &findings[0],
            VulnFinding::NullDeref {
                address: 0x1000,
                ..
            }
        ));
    }

    #[test]
    fn test_vuln_no_null_deref_concrete_nonzero() {
        let mut vd = VulnDetector::new();
        vd.check_null_deref(0x1000, &bv(0x0040_0000, 64), &[]);
        assert!(vd.findings().is_empty());
    }

    #[test]
    fn test_vuln_null_deref_symbolic() {
        let mut vd = VulnDetector::new();
        vd.check_null_deref(0x2000, &var("ptr"), &[]);
        assert_eq!(vd.findings().len(), 1);
    }

    #[test]
    fn test_vuln_buffer_overflow_concrete_oob() {
        let mut vd = VulnDetector::new();
        vd.check_buffer_overflow(0x1000, &bv(10, 32), 8);
        assert_eq!(vd.findings().len(), 1);
        assert!(matches!(
            &vd.findings()[0],
            VulnFinding::BufferOverflow { bound: 8, .. }
        ));
    }

    #[test]
    fn test_vuln_buffer_overflow_concrete_inbounds() {
        let mut vd = VulnDetector::new();
        vd.check_buffer_overflow(0x1000, &bv(3, 32), 8);
        assert!(vd.findings().is_empty());
    }

    #[test]
    fn test_vuln_buffer_overflow_symbolic() {
        let mut vd = VulnDetector::new();
        vd.check_buffer_overflow(0x1000, &var("idx"), 8);
        assert_eq!(vd.findings().len(), 1);
    }

    #[test]
    fn test_vuln_integer_overflow() {
        let mut vd = VulnDetector::new();
        // A 64-bit result being checked against an 8-bit result width
        vd.check_integer_overflow(0x1000, &bv(256, 64), 8);
        assert_eq!(vd.findings().len(), 1);
    }

    #[test]
    fn test_vuln_use_after_free() {
        let mut vd = VulnDetector::new();
        vd.register_free(0xdead_beef);
        vd.check_use_after_free(0x1000, &bv(0xdead_beef, 64));
        assert_eq!(vd.findings().len(), 1);
        assert!(matches!(
            &vd.findings()[0],
            VulnFinding::UseAfterFree { .. }
        ));
    }

    #[test]
    fn test_vuln_no_use_after_free_different_addr() {
        let mut vd = VulnDetector::new();
        vd.register_free(0xdead_beef);
        vd.check_use_after_free(0x1000, &bv(0x0040_0000, 64));
        assert!(vd.findings().is_empty());
    }

    #[test]
    fn test_vuln_format_string_symbolic() {
        let mut vd = VulnDetector::new();
        vd.check_format_string(0x1000, &var("fmt"));
        assert_eq!(vd.findings().len(), 1);
        assert!(matches!(
            &vd.findings()[0],
            VulnFinding::FormatStringBug { .. }
        ));
    }

    #[test]
    fn test_vuln_format_string_const_safe() {
        let mut vd = VulnDetector::new();
        vd.check_format_string(0x1000, &bv(0x0040_1000, 64));
        assert!(vd.findings().is_empty());
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ SymbolicExecutor Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_executor_seed_and_step() {
        let mut exec = SymbolicExecutor::with_default_config();
        exec.seed(0x1000);
        assert_eq!(exec.state_manager.len(), 1);

        // Stepper that advances PC by 4 and terminates.
        let mut stepper = |state: &SymbolicState| {
            if state.pc >= 0x1004 {
                return Ok(vec![]);
            }
            let mut next = state.clone();
            next.pc += 4;
            next.depth += 1;
            Ok(vec![next])
        };

        let result = exec.run(&mut stepper);
        assert!(result.is_ok());
        assert!(exec.visited_addresses.contains(&0x1000));
    }

    #[test]
    fn test_executor_reachability_hit() {
        let mut exec = SymbolicExecutor::with_default_config();
        let mut target = SymbolicState::new();
        target.pc = 0xdead_beef;
        exec.state_manager.push(target);

        let result = exec.check_reachability(
            &ReachabilityQuery {
                target_address: 0xdead_beef,
            },
            &mut |_s| Ok(vec![]),
        );
        assert!(result.unwrap().reachable);
    }

    #[test]
    fn test_executor_reachability_miss() {
        let mut exec = SymbolicExecutor::with_default_config();
        let mut s = SymbolicState::new();
        s.pc = 0x1000;
        exec.state_manager.push(s);

        let result = exec.check_reachability(
            &ReachabilityQuery {
                target_address: 0xdead_beef,
            },
            &mut |_s| Ok(vec![]),
        );
        assert!(!result.unwrap().reachable);
    }

    #[test]
    fn test_executor_apply_summary() {
        let mut exec = SymbolicExecutor::with_default_config();
        let mut summary = FunctionSummary::new(0x5000);
        summary.return_value = Some(bv(99, 64));
        exec.register_summary(summary);

        let mut state = SymbolicState::new();
        let applied = exec.apply_summary(0x5000, &mut state);
        assert!(applied);
        assert_eq!(state.read_register("rax"), bv(99, 64));
    }

    #[test]
    fn test_executor_concretize_constant() {
        let exec = SymbolicExecutor::with_default_config();
        let candidates = exec.concretize_address(&bv(0x4000, 64));
        assert_eq!(candidates, vec![0x4000]);
    }

    #[test]
    fn test_executor_stats() {
        let mut exec = SymbolicExecutor::with_default_config();
        exec.seed(0x1000);
        let stats = exec.stats();
        assert_eq!(stats.live_states, 1);
        assert_eq!(stats.total_enqueued, 1);
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Spec types Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_halt_reason_display() {
        assert_eq!(HaltReason::MaxSteps.to_string(), "MaxSteps");
        assert_eq!(HaltReason::ExplicitHalt.to_string(), "ExplicitHalt");
        assert_eq!(HaltReason::Unreachable.to_string(), "Unreachable");
        assert!(
            HaltReason::Error("oops".to_string())
                .to_string()
                .contains("oops")
        );
    }

    #[test]
    fn test_exec_step_display() {
        assert_eq!(ExecStep::Continue.to_string(), "Continue");
        assert!(
            ExecStep::Halt(HaltReason::MaxSteps)
                .to_string()
                .contains("Halt")
        );
    }

    #[test]
    fn test_sym_op_display() {
        let op = SymOp::Nop;
        assert_eq!(op.to_string(), "nop");
        let op2 = SymOp::Ret;
        assert_eq!(op2.to_string(), "ret");
        let op3 = SymOp::Assign {
            dst: "rax".to_string(),
            src: "rbx".to_string(),
        };
        assert!(op3.to_string().contains("rax"));
    }

    #[test]
    fn test_exec_config_default() {
        let cfg = ExecConfig::default();
        assert!(cfg.max_steps > 0);
        assert!(cfg.max_paths > 0);
    }

    #[test]
    fn test_sym_engine_nop() {
        use rustre_symb::SymState;
        let engine = SymEngine::new(ExecConfig::default());
        let instr = SymInstruction {
            address: 0x1000,
            op: SymOp::Nop,
        };
        let mut state = SymState::new();
        let step = engine.step(&instr, &mut state);
        assert!(matches!(step, ExecStep::Continue));
    }

    #[test]
    fn test_sym_engine_ret() {
        use rustre_symb::SymState;
        let engine = SymEngine::new(ExecConfig::default());
        let instr = SymInstruction {
            address: 0x1000,
            op: SymOp::Ret,
        };
        let mut state = SymState::new();
        let step = engine.step(&instr, &mut state);
        assert!(matches!(step, ExecStep::Halt(HaltReason::ExplicitHalt)));
    }

    #[test]
    fn test_sym_engine_assign() {
        use rustre_symb::{SpecSymExpr, SymState, SymWidth};
        let engine = SymEngine::new(ExecConfig::default());
        let instr = SymInstruction {
            address: 0x1000,
            op: SymOp::Assign {
                dst: "rax".to_string(),
                src: "rbx".to_string(),
            },
        };
        let mut state = SymState::new();
        state.set_var(
            "rbx",
            SpecSymExpr::Const {
                val: 42,
                width: SymWidth::W64,
            },
        );
        let step = engine.step(&instr, &mut state);
        assert!(matches!(step, ExecStep::Continue));
        assert!(state.get_var("rax").is_some());
    }

    #[test]
    fn test_path_explorer_basic() {
        use rustre_symb::SymState;
        let program = vec![
            SymInstruction {
                address: 0x1000,
                op: SymOp::Nop,
            },
            SymInstruction {
                address: 0x1001,
                op: SymOp::Ret,
            },
        ];
        let engine = SymEngine::new(ExecConfig::default());
        let mut explorer = PathExplorer::new(engine);
        explorer.push_state(SymState::new(), vec![]);
        let results = explorer.explore(&program);
        assert!(!results.is_empty());
        assert_eq!(results[0].steps, 2);
    }

    #[test]
    fn test_path_result_is_complete() {
        use rustre_symb::SymState;
        let r = PathResult {
            final_state: SymState::new(),
            path: vec![],
            steps: 0,
            halt: HaltReason::ExplicitHalt,
        };
        assert!(r.is_complete());
        let r2 = PathResult {
            final_state: SymState::new(),
            path: vec![],
            steps: 0,
            halt: HaltReason::Error("x".to_string()),
        };
        assert!(!r2.is_complete());
    }

    #[test]
    fn test_spec_engine_error_display() {
        let e = SpecEngineError::StepLimitExceeded(100);
        assert!(e.to_string().contains("100"));
        let e2 = SpecEngineError::PathLimitExceeded(50);
        assert!(e2.to_string().contains("50"));
        let e3 = SpecEngineError::InvalidProgram("bad".to_string());
        assert!(e3.to_string().contains("bad"));
    }

    #[test]
    fn test_sym_engine_execute() {
        use rustre_symb::SymState;
        let program = vec![SymInstruction {
            address: 0x1000,
            op: SymOp::Nop,
        }];
        let engine = SymEngine::new(ExecConfig::default());
        let results = engine.execute(&program, SymState::new());
        assert!(!results.is_empty());
    }

    #[test]
    fn test_path_explorer_pop_next() {
        use rustre_symb::SymState;
        let engine = SymEngine::new(ExecConfig::default());
        let mut explorer = PathExplorer::new(engine);
        assert!(explorer.pop_next().is_none());
        explorer.push_state(SymState::new(), vec![0x1000]);
        let item = explorer.pop_next();
        assert!(item.is_some());
        assert_eq!(item.unwrap().1, vec![0x1000]);
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Real Symbolic Execution Engine Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
//
// Self-contained engine module. Uses its own `SymExpr` / `SymbolicState`
// types so it does not conflict with the `rustre_symb` re-exports used
// elsewhere in this crate.
//
// Public surface:
//   symex::SymExpr          Ã¢â‚¬â€ expression AST with simplification
//   symex::SymbolicState    Ã¢â‚¬â€ per-path execution state
//   symex::ExplorationStrategy (DFS / BFS / CoverageGuided variants)
//   symex::SymExecEngine    Ã¢â‚¬â€ worklist driver
//   symex::ExplorationReport Ã¢â‚¬â€ statistics produced by run_steps

pub mod symex {
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, HashSet, VecDeque};

    // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Bitvector-and-boolean symbolic expression AST.
    ///
    /// # Encoding
    /// `Const(val, width)` Ã¢â‚¬â€ concrete bitvector: `val` with `width` bits.
    /// `Sym(id, width)`    Ã¢â‚¬â€ unconstrained symbolic variable #`id`, `width` bits.
    /// Boolean operations (`Eq`, `Lt`, `Ite`) sit alongside bitvector ops; the
    /// `width` field of `Const` / `Sym` is `1` for boolean values.
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum SymExpr {
        /// A concrete bitvector constant.  `width` is in bits (1Ã¢â‚¬â€œ64).
        Const(u64, u8),
        /// An unconstrained symbolic input. `id` is globally unique per session.
        Sym(u32, u8),
        /// Addition (wrapping, same width).
        Add(Box<Self>, Box<Self>),
        /// Subtraction (wrapping, same width).
        Sub(Box<Self>, Box<Self>),
        /// Multiplication (wrapping, same width).
        Mul(Box<Self>, Box<Self>),
        /// Bitwise AND.
        And(Box<Self>, Box<Self>),
        /// Bitwise OR.
        Or(Box<Self>, Box<Self>),
        /// Bitwise XOR.
        Xor(Box<Self>, Box<Self>),
        /// Bitwise NOT (one's complement).
        Not(Box<Self>),
        /// Equality comparison Ã¢â‚¬â€ result width is 1.
        Eq(Box<Self>, Box<Self>),
        /// Unsigned less-than Ã¢â‚¬â€ result width is 1.
        Lt(Box<Self>, Box<Self>),
        /// If-then-else.  `cond` should be 1-bit; `then` and `else` must match.
        Ite(Box<Self>, Box<Self>, Box<Self>),
    }

    impl SymExpr {
        // Ã¢â€â‚¬Ã¢â€â‚¬ Helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        /// Return `true` when the expression evaluates to a concrete value
        /// without any symbolic variables.
        #[must_use]
        pub fn is_concrete(&self) -> bool {
            match self {
                Self::Const(..) => true,
                Self::Sym(..) => false,
                Self::Not(e) => e.is_concrete(),
                Self::Add(a, b)
                | Self::Sub(a, b)
                | Self::Mul(a, b)
                | Self::And(a, b)
                | Self::Or(a, b)
                | Self::Xor(a, b)
                | Self::Eq(a, b)
                | Self::Lt(a, b) => a.is_concrete() && b.is_concrete(),
                Self::Ite(c, t, e) => c.is_concrete() && t.is_concrete() && e.is_concrete(),
            }
        }

        /// Return the concrete `u64` value if and only if this expression is a
        /// `Const` node (no evaluation is performed on compound expressions).
        #[must_use]
        pub const fn as_const(&self) -> Option<u64> {
            match self {
                Self::Const(v, _) => Some(*v),
                _ => None,
            }
        }

        /// Return the bit-width hint for this expression node.
        #[must_use]
        pub fn width(&self) -> u8 {
            match self {
                Self::Const(_, w) | Self::Sym(_, w) => *w,
                Self::Not(e) => e.width(),
                Self::Add(a, _)
                | Self::Sub(a, _)
                | Self::Mul(a, _)
                | Self::And(a, _)
                | Self::Or(a, _)
                | Self::Xor(a, _) => a.width(),
                // Comparison results are 1-bit boolean-like.
                Self::Eq(..) | Self::Lt(..) => 1,
                Self::Ite(_, t, _) => t.width(),
            }
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Constant-folding simplifier Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        /// Return a simplified copy of this expression.
        ///
        /// Rules applied (one pass, recursive):
        ///
        /// | Pattern                    | Result              |
        /// |----------------------------|---------------------|
        /// | `Const + Const`            | folded constant     |
        /// | `Const - Const`            | folded constant     |
        /// | `Const * Const`            | folded constant     |
        /// | `Const & Const`            | folded constant     |
        /// | `Const | Const`            | folded constant     |
        /// | `Const ^ Const`            | folded constant     |
        /// | `~Const`                   | folded constant     |
        /// | `x ^ x`                   | 0 (same width)      |
        /// | `x & 0` / `0 & x`         | 0                   |
        /// | `x | 0` / `0 | x`         | x                   |
        /// | `x + 0` / `0 + x`         | x                   |
        /// | `x - 0`                    | x                   |
        /// | `x - x`                    | 0                   |
        /// | `x * 0` / `0 * x`         | 0                   |
        /// | `x * 1` / `1 * x`         | x                   |
        /// | `Eq(Const, Const)`         | Const(0/1, 1)       |
        /// | `Lt(Const, Const)`         | Const(0/1, 1)       |
        /// | `Ite(ConstÃ¢â€°Â 0, t, _)`      | t                   |
        /// | `Ite(Const==0, _, e)`      | e                   |
        #[must_use]
        fn simplify_arith2(&self) -> Self {
            match self {
                Self::Add(l, r) => {
                    let (ls, rs) = (l.simplify(), r.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, rw)) if lw == rw => Self::Const(lv.wrapping_add(*rv) & mask(*lw), *lw),
                        (_, Self::Const(0, _)) => ls,
                        (Self::Const(0, _), _) => rs,
                        _ => Self::Add(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Sub(l, r) => {
                    let (ls, rs) = (l.simplify(), r.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, rw)) if lw == rw => Self::Const(lv.wrapping_sub(*rv) & mask(*lw), *lw),
                        (_, Self::Const(0, _)) => ls,
                        _ if ls == rs => Self::Const(0, ls.width()),
                        _ => Self::Sub(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Mul(l, r) => {
                    let (ls, rs) = (l.simplify(), r.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, rw)) if lw == rw => Self::Const(lv.wrapping_mul(*rv) & mask(*lw), *lw),
                        (Self::Const(0, w), _) | (_, Self::Const(0, w)) => Self::Const(0, *w),
                        (Self::Const(1, _), _) => rs,
                        (_, Self::Const(1, _)) => ls,
                        _ => Self::Mul(Box::new(ls), Box::new(rs)),
                    }
                }
                _ => unreachable!(),
            }
        }

        fn simplify_bitwise2(&self) -> Self {
            match self {
                Self::And(l, r) => {
                    let (ls, rs) = (l.simplify(), r.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, rw)) if lw == rw => Self::Const(lv & rv, *lw),
                        (Self::Const(0, w), _) | (_, Self::Const(0, w)) => Self::Const(0, *w),
                        _ if ls == rs => ls,
                        _ => Self::And(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Or(l, r) => {
                    let (ls, rs) = (l.simplify(), r.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, rw)) if lw == rw => Self::Const(lv | rv, *lw),
                        (_, Self::Const(0, _)) => ls,
                        (Self::Const(0, _), _) => rs,
                        _ if ls == rs => ls,
                        _ => Self::Or(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Xor(l, r) => {
                    let (ls, rs) = (l.simplify(), r.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, rw)) if lw == rw => Self::Const(lv ^ rv, *lw),
                        _ if ls == rs => Self::Const(0, ls.width()),
                        _ => Self::Xor(Box::new(ls), Box::new(rs)),
                    }
                }
                _ => unreachable!(),
            }
        }

        #[must_use]
        pub fn simplify(&self) -> Self {
            match self {
                Self::Const(..) | Self::Sym(..) => self.clone(),
                Self::Not(inner) => {
                    let s = inner.simplify();
                    match s {
                        Self::Const(v, w) => Self::Const((!v) & mask(w), w),
                        Self::Not(inner2) => *inner2,
                        other => Self::Not(Box::new(other)),
                    }
                }
                Self::Add(..) | Self::Sub(..) | Self::Mul(..) => self.simplify_arith2(),
                Self::And(..) | Self::Or(..) | Self::Xor(..) => self.simplify_bitwise2(),
                Self::Eq(l, r) => {
                    let (ls, rs) = (l.simplify(), r.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, _), Self::Const(rv, _)) => Self::Const(u64::from(lv == rv), 1),
                        _ if ls == rs => Self::Const(1, 1),
                        _ => Self::Eq(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Lt(l, r) => {
                    let (ls, rs) = (l.simplify(), r.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, _), Self::Const(rv, _)) => Self::Const(u64::from(lv < rv), 1),
                        _ => Self::Lt(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Ite(cond, then_, else_) => {
                    let cs = cond.simplify();
                    match &cs {
                        Self::Const(0, _) => else_.simplify(),
                        Self::Const(_, _) => then_.simplify(),
                        _ => Self::Ite(Box::new(cs), Box::new(then_.simplify()), Box::new(else_.simplify())),
                    }
                }
            }
        }
    }

    /// Compute the bit mask for a given width (1Ã¢â‚¬â€œ64).
    #[inline]
    const fn mask(w: u8) -> u64 {
        if w == 0 {
            return 0;
        }
        if w >= 64 {
            u64::MAX
        } else {
            (1u64 << w).wrapping_sub(1)
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ SymbolicState Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Per-path symbolic execution state.
    ///
    /// Each field is cheap to clone (`HashMap`) so that forking at branch points
    /// is straightforward.  In a production engine you would use copy-on-write
    /// or persistent data structures, but clarity is preferred here.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SymbolicState {
        /// Register file: register id Ã¢â€ â€™ symbolic expression.
        pub registers: HashMap<u32, SymExpr>,
        /// Concrete-address memory map: address Ã¢â€ â€™ symbolic expression.
        pub memory: HashMap<u64, SymExpr>,
        /// Accumulated path constraints (conjunction must be satisfiable).
        pub path_constraints: Vec<SymExpr>,
        /// Current program counter.
        pub pc: u64,
        /// Depth in the exploration tree (incremented at each branch).
        pub depth: u32,
        /// Unique identifier for this state instance.
        pub id: u32,
    }

    impl SymbolicState {
        /// Create a fresh state at `entry` with the given `state_id`.
        #[must_use]
        pub fn new(entry: u64, state_id: u32) -> Self {
            Self {
                registers: HashMap::new(),
                memory: HashMap::new(),
                path_constraints: Vec::new(),
                pc: entry,
                depth: 0,
                id: state_id,
            }
        }

        /// Fork this state for a new branch, assigning `new_id` to the child.
        ///
        /// The child inherits all registers, memory, and path constraints.
        /// The caller should push a branch-specific constraint before enqueueing
        /// the new state.
        #[must_use]
        pub fn clone_branch(&self, new_id: u32) -> Self {
            Self {
                registers: self.registers.clone(),
                memory: self.memory.clone(),
                path_constraints: self.path_constraints.clone(),
                pc: self.pc,
                depth: self.depth + 1,
                id: new_id,
            }
        }

        /// Append a constraint to the path condition.
        pub fn add_constraint(&mut self, e: SymExpr) {
            self.path_constraints.push(e);
        }

        /// Read register `id`, returning a default `Sym(id, 64)` when unknown.
        #[must_use]
        pub fn read_reg(&self, id: u32) -> SymExpr {
            self.registers
                .get(&id)
                .cloned()
                .unwrap_or(SymExpr::Sym(id, 64))
        }

        /// Write a value into register `id`.
        pub fn write_reg(&mut self, id: u32, val: SymExpr) {
            self.registers.insert(id, val);
        }

        /// Load a byte-sized symbolic value from `address`.
        ///
        /// If no value has been written, a fresh `Sym` variable is synthesised
        /// so that every load is always defined.
        #[must_use]
        pub fn load_mem(&self, address: u64, sym_id: u32) -> SymExpr {
            self.memory
                .get(&address)
                .cloned()
                .unwrap_or(SymExpr::Sym(sym_id, 8))
        }

        /// Store a symbolic value at `address`.
        pub fn store_mem(&mut self, address: u64, val: SymExpr) {
            self.memory.insert(address, val);
        }

        /// Return `true` if any path constraint is trivially false.
        #[must_use]
        pub fn is_infeasible(&self) -> bool {
            self.path_constraints
                .iter()
                .any(|c| matches!(c, SymExpr::Const(0, _)))
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ ExplorationStrategy Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Worklist ordering strategy.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum ExplorationStrategy {
        /// Depth-first search.  States are stored in a stack (LIFO).
        DFS { max_depth: u32 },
        /// Breadth-first search.  States are stored in a queue (FIFO).
        BFS,
        /// Coverage-guided: prefer states at program counters not yet visited.
        CoverageGuided,
    }

    impl ExplorationStrategy {
        /// Return the depth limit, or `u32::MAX` if the strategy has none.
        #[must_use]
        pub const fn max_depth(&self) -> u32 {
            match self {
                Self::DFS { max_depth } => *max_depth,
                _ => u32::MAX,
            }
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ ExplorationReport Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Summary statistics produced by [`SymExecEngine::run_steps`].
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct ExplorationReport {
        /// Total number of distinct execution paths completed (worklist drained or
        /// halted at depth limit).
        pub paths_explored: u32,
        /// Sorted, deduplicated list of all program-counter values visited across
        /// all paths.
        pub unique_pcs: Vec<u64>,
        /// Total number of branch forks created.
        pub branch_count: u32,
        /// Maximum exploration depth reached across all states.
        pub max_depth_reached: u32,
    }

    impl ExplorationReport {
        /// Merge `other` statistics into `self` (used when joining sub-reports).
        pub fn merge(&mut self, other: &Self) {
            self.paths_explored += other.paths_explored;
            self.branch_count += other.branch_count;
            self.max_depth_reached = self.max_depth_reached.max(other.max_depth_reached);
            for &pc in &other.unique_pcs {
                if !self.unique_pcs.contains(&pc) {
                    self.unique_pcs.push(pc);
                }
            }
            self.unique_pcs.sort_unstable();
            self.unique_pcs.dedup();
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ SymExecEngine Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Worklist-driven symbolic execution engine.
    ///
    /// # Lifecycle
    ///
    /// 1. Build with [`SymExecEngine::new`].
    /// 2. Create an initial state with [`SymbolicState::new`] and push it via
    ///    [`SymExecEngine::push_state`].
    /// 3. Drive exploration with [`SymExecEngine::run_steps`] or execute
    ///    individual operations (`exec_add`, `exec_branch`, Ã¢â‚¬Â¦).
    ///
    /// The engine is deliberately **architecture-independent**: it operates on
    /// abstract symbolic operations, not on decoded machine instructions.
    #[derive(Debug)]
    pub struct SymExecEngine {
        /// Active symbolic states (the worklist).
        ///
        /// * DFS   Ã¢â€ â€™ treated as a stack (push / pop from the back).
        /// * BFS   Ã¢â€ â€™ treated as a queue (push back, pop front).
        /// * `CoverageGuided` Ã¢â€ â€™ push back, prefer front states whose `pc` is
        ///   not yet in `explored_pcs`.
        states: VecDeque<SymbolicState>,
        /// All program counters visited across all paths.
        pub explored_pcs: HashSet<u64>,
        /// Exploration ordering strategy.
        pub strategy: ExplorationStrategy,
        /// Maximum number of live states in the worklist at any time.
        pub max_states: usize,
        /// Monotonically increasing state-id counter.
        next_state_id: u32,
        /// Monotonically increasing symbolic-variable-id counter.
        next_sym_id: u32,
    }

    impl SymExecEngine {
        /// Create a new engine.
        ///
        /// * `strategy`   Ã¢â‚¬â€ worklist ordering.
        /// * `max_states` Ã¢â‚¬â€ hard cap on the worklist size (prevents memory blowup).
        #[must_use]
        pub fn new(strategy: ExplorationStrategy, max_states: usize) -> Self {
            Self {
                states: VecDeque::new(),
                explored_pcs: HashSet::new(),
                strategy,
                max_states,
                next_state_id: 0,
                next_sym_id: 0,
            }
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ State management Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        /// Push a state onto the worklist.  States exceeding `max_states` are
        /// silently dropped to enforce the configured bound.
        pub fn push_state(&mut self, state: SymbolicState) {
            if self.states.len() < self.max_states {
                self.states.push_back(state);
            }
        }

        /// Pop the next state from the worklist according to the strategy.
        pub fn pop_state(&mut self) -> Option<SymbolicState> {
            match &self.strategy {
                ExplorationStrategy::DFS { .. } => {
                    // LIFO Ã¢â‚¬â€ pop from back.
                    self.states.pop_back()
                }
                ExplorationStrategy::BFS => {
                    // FIFO Ã¢â‚¬â€ pop from front.
                    self.states.pop_front()
                }
                ExplorationStrategy::CoverageGuided => {
                    // Prefer a state whose `pc` is not yet explored.
                    let preferred = self
                        .states
                        .iter()
                        .position(|s| !self.explored_pcs.contains(&s.pc));
                    if let Some(idx) = preferred {
                        self.states.remove(idx)
                    } else {
                        // All states cover already-visited PCs Ã¢â‚¬â€ fall back to FIFO.
                        self.states.pop_front()
                    }
                }
            }
        }

        /// Allocate a fresh unconstrained symbolic variable of `size` bits.
        #[must_use]
        pub const fn make_symbolic(&mut self, size: u8) -> SymExpr {
            let id = self.next_sym_id;
            self.next_sym_id += 1;
            SymExpr::Sym(id, size)
        }

        /// Allocate the next state id.
        const fn alloc_state_id(&mut self) -> u32 {
            let id = self.next_state_id;
            self.next_state_id += 1;
            id
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Symbolic operations Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        /// Perform a symbolic addition `a + b` and write the result into `dst`.
        ///
        /// Constant folding is applied automatically via [`SymExpr::simplify`].
        pub fn exec_add(&mut self, state: &mut SymbolicState, dst: u32, a: SymExpr, b: SymExpr) {
            let result = SymExpr::Add(Box::new(a), Box::new(b)).simplify();
            state.write_reg(dst, result);
        }

        /// Perform a symbolic subtraction `a - b` and write the result into `dst`.
        pub fn exec_sub(&mut self, state: &mut SymbolicState, dst: u32, a: SymExpr, b: SymExpr) {
            let result = SymExpr::Sub(Box::new(a), Box::new(b)).simplify();
            state.write_reg(dst, result);
        }

        /// Perform a symbolic AND `a & b` and write the result into `dst`.
        pub fn exec_and(&mut self, state: &mut SymbolicState, dst: u32, a: SymExpr, b: SymExpr) {
            let result = SymExpr::And(Box::new(a), Box::new(b)).simplify();
            state.write_reg(dst, result);
        }

        /// Perform a symbolic OR `a | b` and write the result into `dst`.
        pub fn exec_or(&mut self, state: &mut SymbolicState, dst: u32, a: SymExpr, b: SymExpr) {
            let result = SymExpr::Or(Box::new(a), Box::new(b)).simplify();
            state.write_reg(dst, result);
        }

        /// Perform a symbolic XOR `a ^ b` and write the result into `dst`.
        pub fn exec_xor(&mut self, state: &mut SymbolicState, dst: u32, a: SymExpr, b: SymExpr) {
            let result = SymExpr::Xor(Box::new(a), Box::new(b)).simplify();
            state.write_reg(dst, result);
        }

        /// Perform a symbolic multiplication `a * b` and write the result into `dst`.
        pub fn exec_mul(&mut self, state: &mut SymbolicState, dst: u32, a: SymExpr, b: SymExpr) {
            let result = SymExpr::Mul(Box::new(a), Box::new(b)).simplify();
            state.write_reg(dst, result);
        }

        /// Fork execution at a conditional branch.
        ///
        /// Two new child states are created from `state`:
        ///
        /// * **taken**     Ã¢â‚¬â€ `cond` is added as a positive constraint; `pc` is set
        ///   to `taken_pc`.
        /// * **not-taken** Ã¢â‚¬â€ `Not(cond)` is added as a constraint; `pc` is set to
        ///   `not_taken_pc`.
        ///
        /// Both children are pushed onto the worklist (subject to `max_states`).
        /// Trivially infeasible children (where the added constraint is
        /// `Const(0, 1)`) are pruned before being pushed.
        pub fn exec_branch(
            &mut self,
            state: &SymbolicState,
            cond: SymExpr,
            taken_pc: u64,
            not_taken_pc: u64,
        ) {
            // Ã¢â€â‚¬Ã¢â€â‚¬ Taken branch Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            let taken_id = self.alloc_state_id();
            let mut taken = state.clone_branch(taken_id);
            taken.pc = taken_pc;
            let taken_cond = cond.simplify();
            // Only add constraint if non-trivial.
            if !matches!(taken_cond, SymExpr::Const(1, _)) {
                taken.add_constraint(taken_cond);
            }
            if !taken.is_infeasible() {
                self.push_state(taken);
            }

            // Ã¢â€â‚¬Ã¢â€â‚¬ Not-taken branch Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            let not_taken_id = self.alloc_state_id();
            let mut not_taken = state.clone_branch(not_taken_id);
            not_taken.pc = not_taken_pc;
            let not_taken_cond = SymExpr::Not(Box::new(cond)).simplify();
            if !matches!(not_taken_cond, SymExpr::Const(1, _)) {
                not_taken.add_constraint(not_taken_cond);
            }
            if !not_taken.is_infeasible() {
                self.push_state(not_taken);
            }
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Exploration loop Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        /// Drive exploration for up to `steps` "ticks".
        ///
        /// Each tick pops a state and performs one abstract action:
        /// - Records `state.pc` as explored.
        /// - If the depth limit is exceeded the state is counted as a completed
        ///   path and discarded.
        /// - Otherwise a synthetic branch is created at the current PC so that
        ///   coverage statistics are non-trivial.  (In a real integration the
        ///   caller would decode an instruction and call `exec_branch` /
        ///   `exec_add` etc. manually; the loop here is a self-contained demo.)
        ///
        /// Returns an [`ExplorationReport`] summarising all activity during the
        /// call.
        #[must_use]
        pub fn run_steps(&mut self, steps: u32) -> ExplorationReport {
            let mut report = ExplorationReport::default();

            for _ in 0..steps {
                let Some(state) = self.pop_state() else {
                    break;
                };

                let pc = state.pc;
                let is_new_pc = self.explored_pcs.insert(pc);
                if is_new_pc && !report.unique_pcs.contains(&pc) {
                    report.unique_pcs.push(pc);
                }

                let depth_limit = self.strategy.max_depth();
                if state.depth >= depth_limit {
                    // Depth limit hit Ã¢â‚¬â€ count as a completed path.
                    report.paths_explored += 1;
                    report.max_depth_reached = report.max_depth_reached.max(state.depth);
                    continue;
                }

                report.max_depth_reached = report.max_depth_reached.max(state.depth);

                // Ã¢â€â‚¬Ã¢â€â‚¬ Synthesise a branch to keep the worklist growing Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
                //
                // In a real integration the caller controls instruction
                // dispatch; here we create a symbolic condition and fork so
                // that the engine demonstrates branching behaviour without
                // requiring a decoded instruction stream.
                let sym_cond = self.make_symbolic(1);
                let taken_pc = pc.wrapping_add(4); // "next instruction"
                let not_taken_pc = pc.wrapping_add(8); // "branch target"

                // Snapshot before branching.
                let pre_branch_state = state.clone();

                // Check if cond is concrete (it won't be for a fresh Sym, but
                // handles callers who pass concrete states).
                match sym_cond.simplify().as_const() {
                    Some(0) => {
                        // Statically not-taken Ã¢â‚¬â€ just advance.
                        let id = self.alloc_state_id();
                        let mut next = pre_branch_state.clone_branch(id);
                        next.pc = not_taken_pc;
                        self.push_state(next);
                    }
                    Some(_) => {
                        // Statically taken.
                        let id = self.alloc_state_id();
                        let mut next = pre_branch_state.clone_branch(id);
                        next.pc = taken_pc;
                        self.push_state(next);
                    }
                    None => {
                        // Symbolic condition Ã¢â‚¬â€ fork.
                        self.exec_branch(&pre_branch_state, sym_cond, taken_pc, not_taken_pc);
                        report.branch_count += 1;
                    }
                }
            }

            // Sort and dedup the PC list for deterministic output.
            report.unique_pcs.sort_unstable();
            report.unique_pcs.dedup();

            report
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Accessors Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        /// Number of states currently in the worklist.
        #[must_use]
        pub fn live_state_count(&self) -> usize {
            self.states.len()
        }

        /// `true` when the worklist is empty.
        #[must_use]
        pub fn is_exhausted(&self) -> bool {
            self.states.is_empty()
        }

        /// `true` when the worklist is at capacity.
        #[must_use]
        pub fn is_full(&self) -> bool {
            self.states.len() >= self.max_states
        }

        /// Total unique program-counter values seen so far.
        #[must_use]
        pub fn coverage(&self) -> usize {
            self.explored_pcs.len()
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Tests Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[cfg(test)]
    mod tests {
        use super::*;

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        fn c64(v: u64) -> SymExpr {
            SymExpr::Const(v, 64)
        }
        fn c8(v: u64) -> SymExpr {
            SymExpr::Const(v, 8)
        }
        fn s64(id: u32) -> SymExpr {
            SymExpr::Sym(id, 64)
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::is_concrete Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        #[test]
        fn sym_expr_is_concrete_const() {
            assert!(c64(42).is_concrete());
        }

        #[test]
        fn sym_expr_is_concrete_sym() {
            assert!(!s64(0).is_concrete());
        }

        #[test]
        fn sym_expr_is_concrete_add_consts() {
            let e = SymExpr::Add(Box::new(c64(1)), Box::new(c64(2)));
            assert!(e.is_concrete());
        }

        #[test]
        fn sym_expr_is_concrete_add_sym() {
            let e = SymExpr::Add(Box::new(c64(1)), Box::new(s64(0)));
            assert!(!e.is_concrete());
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::as_const Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        #[test]
        fn sym_expr_as_const_some() {
            assert_eq!(c64(7).as_const(), Some(7));
        }

        #[test]
        fn sym_expr_as_const_none_for_sym() {
            assert_eq!(s64(0).as_const(), None);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::simplify Ã¢â‚¬â€ arithmetic Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        #[test]
        fn simplify_add_constants() {
            let e = SymExpr::Add(Box::new(c64(3)), Box::new(c64(4)));
            assert_eq!(e.simplify(), c64(7));
        }

        #[test]
        fn simplify_add_zero_right() {
            let e = SymExpr::Add(Box::new(s64(0)), Box::new(c64(0)));
            assert_eq!(e.simplify(), s64(0));
        }

        #[test]
        fn simplify_add_zero_left() {
            let e = SymExpr::Add(Box::new(c64(0)), Box::new(s64(1)));
            assert_eq!(e.simplify(), s64(1));
        }

        #[test]
        fn simplify_sub_constants() {
            let e = SymExpr::Sub(Box::new(c64(10)), Box::new(c64(3)));
            assert_eq!(e.simplify(), c64(7));
        }

        #[test]
        fn simplify_sub_self() {
            let e = SymExpr::Sub(Box::new(s64(0)), Box::new(s64(0)));
            assert_eq!(e.simplify(), SymExpr::Const(0, 64));
        }

        #[test]
        fn simplify_sub_zero() {
            let e = SymExpr::Sub(Box::new(s64(5)), Box::new(c64(0)));
            assert_eq!(e.simplify(), s64(5));
        }

        #[test]
        fn simplify_mul_constants() {
            let e = SymExpr::Mul(Box::new(c64(6)), Box::new(c64(7)));
            assert_eq!(e.simplify(), c64(42));
        }

        #[test]
        fn simplify_mul_zero() {
            let e = SymExpr::Mul(Box::new(s64(0)), Box::new(c64(0)));
            assert_eq!(e.simplify().as_const(), Some(0));
        }

        #[test]
        fn simplify_mul_one() {
            let e = SymExpr::Mul(Box::new(s64(3)), Box::new(c64(1)));
            assert_eq!(e.simplify(), s64(3));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::simplify Ã¢â‚¬â€ bitwise Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        #[test]
        fn simplify_and_zero() {
            let e = SymExpr::And(Box::new(s64(0)), Box::new(c64(0)));
            assert_eq!(e.simplify().as_const(), Some(0));
        }

        #[test]
        fn simplify_and_self() {
            let e = SymExpr::And(Box::new(s64(2)), Box::new(s64(2)));
            assert_eq!(e.simplify(), s64(2));
        }

        #[test]
        fn simplify_or_zero() {
            let e = SymExpr::Or(Box::new(s64(1)), Box::new(c64(0)));
            assert_eq!(e.simplify(), s64(1));
        }

        #[test]
        fn simplify_or_self() {
            let e = SymExpr::Or(Box::new(s64(7)), Box::new(s64(7)));
            assert_eq!(e.simplify(), s64(7));
        }

        #[test]
        fn simplify_xor_self_is_zero() {
            let e = SymExpr::Xor(Box::new(s64(4)), Box::new(s64(4)));
            assert_eq!(e.simplify(), SymExpr::Const(0, 64));
        }

        #[test]
        fn simplify_not_const() {
            // ~0u8 = 0xFF
            let e = SymExpr::Not(Box::new(c8(0)));
            assert_eq!(e.simplify(), c8(0xFF));
        }

        #[test]
        fn simplify_double_not() {
            // ~~x = x
            let inner = s64(99);
            let e = SymExpr::Not(Box::new(SymExpr::Not(Box::new(inner.clone()))));
            assert_eq!(e.simplify(), inner);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::simplify Ã¢â‚¬â€ comparison Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        #[test]
        fn simplify_eq_constants_equal() {
            let e = SymExpr::Eq(Box::new(c64(5)), Box::new(c64(5)));
            assert_eq!(e.simplify(), SymExpr::Const(1, 1));
        }

        #[test]
        fn simplify_eq_constants_unequal() {
            let e = SymExpr::Eq(Box::new(c64(5)), Box::new(c64(6)));
            assert_eq!(e.simplify(), SymExpr::Const(0, 1));
        }

        #[test]
        fn simplify_eq_self() {
            let e = SymExpr::Eq(Box::new(s64(8)), Box::new(s64(8)));
            assert_eq!(e.simplify(), SymExpr::Const(1, 1));
        }

        #[test]
        fn simplify_lt_constants() {
            let less = SymExpr::Lt(Box::new(c64(3)), Box::new(c64(7)));
            assert_eq!(less.simplify(), SymExpr::Const(1, 1));
            let not_less = SymExpr::Lt(Box::new(c64(9)), Box::new(c64(2)));
            assert_eq!(not_less.simplify(), SymExpr::Const(0, 1));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::simplify Ã¢â‚¬â€ ITE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        #[test]
        fn simplify_ite_true_cond() {
            // ITE(1, c64(42), c64(0)) = c64(42)
            let e = SymExpr::Ite(
                Box::new(SymExpr::Const(1, 1)),
                Box::new(c64(42)),
                Box::new(c64(0)),
            );
            assert_eq!(e.simplify(), c64(42));
        }

        #[test]
        fn simplify_ite_false_cond() {
            let e = SymExpr::Ite(
                Box::new(SymExpr::Const(0, 1)),
                Box::new(c64(99)),
                Box::new(c64(7)),
            );
            assert_eq!(e.simplify(), c64(7));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymbolicState Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        #[test]
        fn state_read_unset_reg_returns_sym() {
            let state = SymbolicState::new(0x1000, 0);
            let val = state.read_reg(42);
            assert!(matches!(val, SymExpr::Sym(42, 64)));
        }

        #[test]
        fn state_write_then_read_reg() {
            let mut state = SymbolicState::new(0, 0);
            state.write_reg(0, c64(999));
            assert_eq!(state.read_reg(0), c64(999));
        }

        #[test]
        fn state_add_constraint() {
            let mut state = SymbolicState::new(0, 0);
            assert!(state.path_constraints.is_empty());
            state.add_constraint(SymExpr::Const(1, 1));
            assert_eq!(state.path_constraints.len(), 1);
        }

        #[test]
        fn state_is_infeasible_false_constraint() {
            let mut state = SymbolicState::new(0, 0);
            state.add_constraint(SymExpr::Const(0, 1));
            assert!(state.is_infeasible());
        }

        #[test]
        fn state_is_infeasible_no_constraint() {
            let state = SymbolicState::new(0, 0);
            assert!(!state.is_infeasible());
        }

        #[test]
        fn state_clone_branch_increments_depth() {
            // SymbolicState::new starts with depth=0; clone_branch adds 1.
            let state = SymbolicState::new(0x2000, 5);
            assert_eq!(state.depth, 0);
            let child = state.clone_branch(99);
            assert_eq!(child.depth, 1);
            assert_eq!(child.id, 99);
            assert_eq!(child.pc, 0x2000);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ ExplorationStrategy Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        #[test]
        fn exploration_strategy_max_depth_dfs() {
            let s = ExplorationStrategy::DFS { max_depth: 128 };
            assert_eq!(s.max_depth(), 128);
        }

        #[test]
        fn exploration_strategy_max_depth_bfs() {
            assert_eq!(ExplorationStrategy::BFS.max_depth(), u32::MAX);
        }

        #[test]
        fn exploration_strategy_max_depth_coverage() {
            assert_eq!(ExplorationStrategy::CoverageGuided.max_depth(), u32::MAX);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExecEngine Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        #[test]
        fn engine_make_symbolic_increments_id() {
            let mut engine = SymExecEngine::new(ExplorationStrategy::BFS, 1024);
            let s0 = engine.make_symbolic(64);
            let s1 = engine.make_symbolic(32);
            assert!(matches!(s0, SymExpr::Sym(0, 64)));
            assert!(matches!(s1, SymExpr::Sym(1, 32)));
        }

        #[test]
        fn engine_push_pop_dfs_lifo() {
            let mut engine = SymExecEngine::new(ExplorationStrategy::DFS { max_depth: 10 }, 1024);
            let s1 = SymbolicState::new(0x1000, 0);
            let s2 = SymbolicState::new(0x2000, 1);
            engine.push_state(s1);
            engine.push_state(s2);
            let popped = engine.pop_state().unwrap();
            assert_eq!(popped.pc, 0x2000); // LIFO
        }

        #[test]
        fn engine_push_pop_bfs_fifo() {
            let mut engine = SymExecEngine::new(ExplorationStrategy::BFS, 1024);
            let s1 = SymbolicState::new(0x1000, 0);
            let s2 = SymbolicState::new(0x2000, 1);
            engine.push_state(s1);
            engine.push_state(s2);
            let popped = engine.pop_state().unwrap();
            assert_eq!(popped.pc, 0x1000); // FIFO
        }

        #[test]
        fn engine_max_states_cap() {
            let mut engine = SymExecEngine::new(ExplorationStrategy::BFS, 2);
            for i in 0..10u32 {
                engine.push_state(SymbolicState::new(u64::from(i), i));
            }
            assert_eq!(engine.live_state_count(), 2);
        }

        #[test]
        fn engine_exec_add_const_folding() {
            let mut engine = SymExecEngine::new(ExplorationStrategy::BFS, 64);
            let mut state = SymbolicState::new(0, 0);
            engine.exec_add(&mut state, 0, c64(10), c64(32));
            assert_eq!(state.read_reg(0), c64(42));
        }

        #[test]
        fn engine_exec_branch_creates_two_states() {
            let mut engine = SymExecEngine::new(ExplorationStrategy::BFS, 64);
            let state = SymbolicState::new(0x1000, 0);
            let cond = engine.make_symbolic(1);
            engine.exec_branch(&state, cond, 0x1004, 0x2000);
            assert_eq!(engine.live_state_count(), 2);
        }

        #[test]
        fn engine_exec_branch_taken_pc() {
            let mut engine = SymExecEngine::new(ExplorationStrategy::BFS, 64);
            let state = SymbolicState::new(0x1000, 0);
            // Concrete true condition Ã¢â€ â€™ only taken branch should be pushed.
            let cond = SymExpr::Const(1, 1);
            engine.exec_branch(&state, cond, 0x4000, 0x8000);
            // The taken branch is pushed; the not-taken constraint evaluates to
            // NOT(1) = 0, which is infeasible, so it is pruned.
            let popped = engine.pop_state().unwrap();
            assert_eq!(popped.pc, 0x4000);
        }

        #[test]
        fn engine_exec_branch_not_taken_pc() {
            let mut engine = SymExecEngine::new(ExplorationStrategy::BFS, 64);
            let state = SymbolicState::new(0x1000, 0);
            // Concrete false condition Ã¢â€ â€™ only not-taken branch.
            let cond = SymExpr::Const(0, 1);
            engine.exec_branch(&state, cond, 0x4000, 0x8000);
            let popped = engine.pop_state().unwrap();
            assert_eq!(popped.pc, 0x8000);
        }

        #[test]
        fn engine_run_steps_returns_report() {
            let mut engine = SymExecEngine::new(ExplorationStrategy::DFS { max_depth: 4 }, 256);
            let initial = SymbolicState::new(0x1000, 0);
            engine.push_state(initial);
            let report = engine.run_steps(10);
            assert!(report.paths_explored > 0 || report.branch_count > 0);
            assert!(!report.unique_pcs.is_empty());
        }

        #[test]
        fn engine_run_steps_coverage_grows() {
            let mut engine = SymExecEngine::new(ExplorationStrategy::CoverageGuided, 512);
            let initial = SymbolicState::new(0x5000, 0);
            engine.push_state(initial);
            let _ = engine.run_steps(20);
            // At least the seed PC should have been recorded.
            assert!(engine.explored_pcs.contains(&0x5000));
        }

        #[test]
        fn engine_run_steps_depth_limit() {
            // With DFS max_depth=1 the first state's child should be pruned.
            let mut engine = SymExecEngine::new(ExplorationStrategy::DFS { max_depth: 1 }, 256);
            let initial = SymbolicState::new(0xABCD, 0);
            engine.push_state(initial);
            let report = engine.run_steps(50);
            assert!(report.max_depth_reached >= 1);
        }

        #[test]
        fn engine_coverage_accessor() {
            let mut engine = SymExecEngine::new(ExplorationStrategy::BFS, 64);
            assert_eq!(engine.coverage(), 0);
            let initial = SymbolicState::new(0x100, 0);
            engine.push_state(initial);
            let _ = engine.run_steps(1);
            assert!(engine.coverage() >= 1);
        }

        #[test]
        fn exploration_report_merge() {
            let mut r1 = ExplorationReport {
                paths_explored: 3,
                unique_pcs: vec![0x1000, 0x2000],
                branch_count: 2,
                max_depth_reached: 4,
            };
            let r2 = ExplorationReport {
                paths_explored: 5,
                unique_pcs: vec![0x2000, 0x3000],
                branch_count: 1,
                max_depth_reached: 7,
            };
            r1.merge(&r2);
            assert_eq!(r1.paths_explored, 8);
            assert_eq!(r1.branch_count, 3);
            assert_eq!(r1.max_depth_reached, 7);
            assert!(r1.unique_pcs.contains(&0x1000));
            assert!(r1.unique_pcs.contains(&0x2000));
            assert!(r1.unique_pcs.contains(&0x3000));
            // Dedup: 0x2000 should appear exactly once.
            assert_eq!(r1.unique_pcs.iter().filter(|&&x| x == 0x2000).count(), 1);
        }
    }
}

// Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
// SECTION 13 Ã¢â‚¬â€ Complete Symbolic Execution Engine (info.txt spec)
// Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

/// Self-contained symbolic execution engine (section 13).
pub mod full_symex {

    use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // PART 1 Ã¢â‚¬â€ Symbolic Expression Algebra
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Bitvector symbolic expression with comparators and if-then-else.
    /// All `u8` size fields are in bytes (1, 2, 4, 8).
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum SymExpr {
        Const(u64, u8),
        Symbol(u32, u8),
        Add(Box<Self>, Box<Self>),
        Sub(Box<Self>, Box<Self>),
        Mul(Box<Self>, Box<Self>),
        UDiv(Box<Self>, Box<Self>),
        SDiv(Box<Self>, Box<Self>),
        And(Box<Self>, Box<Self>),
        Or(Box<Self>, Box<Self>),
        Xor(Box<Self>, Box<Self>),
        Shl(Box<Self>, Box<Self>),
        LShr(Box<Self>, Box<Self>),
        AShr(Box<Self>, Box<Self>),
        Not(Box<Self>),
        Neg(Box<Self>),
        ZExt(Box<Self>, u8),
        SExt(Box<Self>, u8),
        Trunc(Box<Self>, u8),
        Concat(Box<Self>, Box<Self>),
        Extract(Box<Self>, u8, u8),
        Load(Box<Self>, u8),
        ITE(Box<Self>, Box<Self>, Box<Self>),
        Eq(Box<Self>, Box<Self>),
        Ne(Box<Self>, Box<Self>),
        Ult(Box<Self>, Box<Self>),
        Ule(Box<Self>, Box<Self>),
        Ugt(Box<Self>, Box<Self>),
        Uge(Box<Self>, Box<Self>),
        Slt(Box<Self>, Box<Self>),
        Sle(Box<Self>, Box<Self>),
        Sgt(Box<Self>, Box<Self>),
        Sge(Box<Self>, Box<Self>),
    }

    #[inline]
    const fn byte_mask(size: u8) -> u64 {
        if size == 0 {
            return 0;
        }
        if size >= 8 {
            return u64::MAX;
        }
        (1u64 << (size as u32 * 8)).wrapping_sub(1)
    }

    #[inline]
    const fn sign_extend(val: u64, from_bytes: u8) -> i64 {
        let bits = from_bytes as u32 * 8;
        if bits == 0 || bits >= 64 {
            return val.cast_signed();
        }
        let shift = 64 - bits;
        ((val << shift).cast_signed()) >> shift
    }

    impl SymExpr {
        #[must_use]
        pub const fn const64(v: u64) -> Self {
            Self::Const(v, 8)
        }
        #[must_use]
        pub const fn const32(v: u32) -> Self {
            Self::Const(v as u64, 4)
        }
        #[must_use]
        pub const fn const8(v: u8) -> Self {
            Self::Const(v as u64, 1)
        }
        #[must_use]
        pub const fn bool_true() -> Self {
            Self::Const(1, 1)
        }
        #[must_use]
        pub const fn bool_false() -> Self {
            Self::Const(0, 1)
        }

        #[must_use]
        pub fn is_concrete(&self) -> bool {
            self.free_symbols().is_empty()
        }
        #[must_use]
        pub const fn as_const(&self) -> Option<u64> {
            match self {
                Self::Const(v, _) => Some(*v),
                _ => None,
            }
        }

        #[must_use]
        pub fn size(&self) -> u8 {
            match self {
                Self::Const(_, s)
                | Self::Symbol(_, s)
                | Self::ZExt(_, s)
                | Self::SExt(_, s)
                | Self::Trunc(_, s)
                | Self::Load(_, s) => *s,
                Self::Add(a, _)
                | Self::Sub(a, _)
                | Self::Mul(a, _)
                | Self::UDiv(a, _)
                | Self::SDiv(a, _)
                | Self::And(a, _)
                | Self::Or(a, _)
                | Self::Xor(a, _)
                | Self::Shl(a, _)
                | Self::LShr(a, _)
                | Self::AShr(a, _) => a.size(),
                Self::Not(e) | Self::Neg(e) => e.size(),
                Self::Concat(hi, lo) => hi.size().saturating_add(lo.size()),
                Self::Extract(_, hi, lo) => {
                    let bits = hi.wrapping_sub(*lo).wrapping_add(1);
                    (bits / 8).max(1)
                }
                Self::ITE(_, t, _) => t.size(),
                Self::Eq(..)
                | Self::Ne(..)
                | Self::Ult(..)
                | Self::Ule(..)
                | Self::Ugt(..)
                | Self::Uge(..)
                | Self::Slt(..)
                | Self::Sle(..)
                | Self::Sgt(..)
                | Self::Sge(..) => 1,
            }
        }

        #[must_use]
        pub fn free_symbols(&self) -> HashSet<u32> {
            let mut out = HashSet::new();
            self.collect_symbols(&mut out);
            out
        }

        fn collect_symbols(&self, out: &mut HashSet<u32>) {
            match self {
                Self::Const(..) => {}
                Self::Symbol(id, _) => {
                    out.insert(*id);
                }
                Self::Not(e)
                | Self::Neg(e)
                | Self::ZExt(e, _)
                | Self::SExt(e, _)
                | Self::Trunc(e, _)
                | Self::Extract(e, _, _)
                | Self::Load(e, _) => e.collect_symbols(out),
                Self::Add(a, b)
                | Self::Sub(a, b)
                | Self::Mul(a, b)
                | Self::UDiv(a, b)
                | Self::SDiv(a, b)
                | Self::And(a, b)
                | Self::Or(a, b)
                | Self::Xor(a, b)
                | Self::Shl(a, b)
                | Self::LShr(a, b)
                | Self::AShr(a, b)
                | Self::Concat(a, b)
                | Self::Eq(a, b)
                | Self::Ne(a, b)
                | Self::Ult(a, b)
                | Self::Ule(a, b)
                | Self::Ugt(a, b)
                | Self::Uge(a, b)
                | Self::Slt(a, b)
                | Self::Sle(a, b)
                | Self::Sgt(a, b)
                | Self::Sge(a, b) => {
                    a.collect_symbols(out);
                    b.collect_symbols(out);
                }
                Self::ITE(c, t, e) => {
                    c.collect_symbols(out);
                    t.collect_symbols(out);
                    e.collect_symbols(out);
                }
            }
        }

        #[must_use]
        pub fn evaluate_concrete(&self, syms: &HashMap<u32, u64>) -> Option<u64> {
            Some(match self {
                Self::Const(v, _) => *v,
                Self::Symbol(id, _) => *syms.get(id)?,
                Self::Not(e) => {
                    let s = e.size();
                    (!e.evaluate_concrete(syms)?) & byte_mask(s)
                }
                Self::Neg(e) => {
                    let s = e.size();
                    (e.evaluate_concrete(syms)?).wrapping_neg() & byte_mask(s)
                }
                Self::Add(a, b) => {
                    let s = a.size();
                    a.evaluate_concrete(syms)?
                        .wrapping_add(b.evaluate_concrete(syms)?)
                        & byte_mask(s)
                }
                Self::Sub(a, b) => {
                    let s = a.size();
                    a.evaluate_concrete(syms)?
                        .wrapping_sub(b.evaluate_concrete(syms)?)
                        & byte_mask(s)
                }
                Self::Mul(a, b) => {
                    let s = a.size();
                    a.evaluate_concrete(syms)?
                        .wrapping_mul(b.evaluate_concrete(syms)?)
                        & byte_mask(s)
                }
                Self::UDiv(a, b) => {
                    let bv = b.evaluate_concrete(syms)?;
                    if bv == 0 {
                        return None;
                    }
                    a.evaluate_concrete(syms)? / bv
                }
                Self::SDiv(a, b) => {
                    let av = sign_extend(a.evaluate_concrete(syms)?, a.size());
                    let bv = sign_extend(b.evaluate_concrete(syms)?, b.size());
                    if bv == 0 {
                        return None;
                    }
                    (av.wrapping_div(bv)).cast_unsigned() & byte_mask(a.size())
                }
                Self::And(a, b) => a.evaluate_concrete(syms)? & b.evaluate_concrete(syms)?,
                Self::Or(a, b) => a.evaluate_concrete(syms)? | b.evaluate_concrete(syms)?,
                Self::Xor(a, b) => a.evaluate_concrete(syms)? ^ b.evaluate_concrete(syms)?,
                Self::Shl(a, b) => {
                    let s = a.size();
                    let sh = u32::try_from(b.evaluate_concrete(syms)?).unwrap_or(u32::MAX);
                    if sh >= (u32::from(s) * 8) {
                        0
                    } else {
                        (a.evaluate_concrete(syms)? << sh) & byte_mask(s)
                    }
                }
                Self::LShr(a, b) => {
                    let sh = u32::try_from(b.evaluate_concrete(syms)?).unwrap_or(u32::MAX);
                    let av = a.evaluate_concrete(syms)?;
                    if sh >= 64 { 0 } else { av >> sh }
                }
                Self::AShr(a, b) => {
                    let sh = u32::try_from(b.evaluate_concrete(syms)?).unwrap_or(u32::MAX);
                    let av = sign_extend(a.evaluate_concrete(syms)?, a.size());
                    if sh >= 64 {
                        if av < 0 { u64::MAX } else { 0 }
                    } else {
                        (av >> sh).cast_unsigned() & byte_mask(a.size())
                    }
                }
                Self::ZExt(e, s) | Self::Trunc(e, s) => e.evaluate_concrete(syms)? & byte_mask(*s),
                Self::SExt(e, s) => {
                    sign_extend(e.evaluate_concrete(syms)?, e.size()).cast_unsigned() & byte_mask(*s)
                }
                Self::Concat(hi, lo) => {
                    let lb = u32::from(lo.size()) * 8;
                    (hi.evaluate_concrete(syms)? << lb) | lo.evaluate_concrete(syms)?
                }
                Self::Extract(e, hi, lo) => {
                    let v = e.evaluate_concrete(syms)?;
                    let bits = hi.wrapping_sub(*lo).wrapping_add(1);
                    let mask = if bits >= 64 {
                        u64::MAX
                    } else {
                        (1u64 << bits) - 1
                    };
                    (v >> lo) & mask
                }
                Self::Load(..) | Self::ITE(..) => return None,
                Self::Eq(..) | Self::Ne(..) | Self::Ult(..) | Self::Ule(..) | Self::Ugt(..)
                | Self::Uge(..) | Self::Slt(..) | Self::Sle(..) | Self::Sgt(..) | Self::Sge(..) => {
                    return self.evaluate_concrete_cmp(syms);
                }
            })
        }

        fn evaluate_concrete_cmp(&self, syms: &HashMap<u32, u64>) -> Option<u64> {
            Some(match self {
                Self::Eq(a, b) => u64::from(a.evaluate_concrete(syms)? == b.evaluate_concrete(syms)?),
                Self::Ne(a, b) => u64::from(a.evaluate_concrete(syms)? != b.evaluate_concrete(syms)?),
                Self::Ult(a, b) => u64::from(a.evaluate_concrete(syms)? < b.evaluate_concrete(syms)?),
                Self::Ule(a, b) => u64::from(a.evaluate_concrete(syms)? <= b.evaluate_concrete(syms)?),
                Self::Ugt(a, b) => u64::from(a.evaluate_concrete(syms)? > b.evaluate_concrete(syms)?),
                Self::Uge(a, b) => u64::from(a.evaluate_concrete(syms)? >= b.evaluate_concrete(syms)?),
                Self::Slt(a, b) => u64::from(sign_extend(a.evaluate_concrete(syms)?, a.size()) < sign_extend(b.evaluate_concrete(syms)?, b.size())),
                Self::Sle(a, b) => u64::from(sign_extend(a.evaluate_concrete(syms)?, a.size()) <= sign_extend(b.evaluate_concrete(syms)?, b.size())),
                Self::Sgt(a, b) => u64::from(sign_extend(a.evaluate_concrete(syms)?, a.size()) > sign_extend(b.evaluate_concrete(syms)?, b.size())),
                Self::Sge(a, b) => u64::from(sign_extend(a.evaluate_concrete(syms)?, a.size()) >= sign_extend(b.evaluate_concrete(syms)?, b.size())),
                _ => unreachable!(),
            })
        }

        fn simplify_unary(&self) -> Self {
            match self {
                Self::Not(inner) => {
                    let s = inner.simplify();
                    match &s {
                        Self::Const(v, w) => Self::Const((!v) & byte_mask(*w), *w),
                        Self::Not(x) => *x.clone(),
                        _ => Self::Not(Box::new(s)),
                    }
                }
                Self::Neg(inner) => {
                    let s = inner.simplify();
                    match &s {
                        Self::Const(v, w) => Self::Const(v.wrapping_neg() & byte_mask(*w), *w),
                        _ => Self::Neg(Box::new(s)),
                    }
                }
                _ => unreachable!(),
            }
        }

        fn simplify_arith(&self) -> Self {
            match self {
                Self::Add(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, _)) => Self::Const(lv.wrapping_add(*rv) & byte_mask(*lw), *lw),
                        (_, Self::Const(0, _)) => ls,
                        (Self::Const(0, _), _) => rs,
                        _ => Self::Add(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Sub(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    if ls == rs { return Self::Const(0, ls.size()); }
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, _)) => Self::Const(lv.wrapping_sub(*rv) & byte_mask(*lw), *lw),
                        (_, Self::Const(0, _)) => ls,
                        _ => Self::Sub(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Mul(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, _)) => Self::Const(lv.wrapping_mul(*rv) & byte_mask(*lw), *lw),
                        (Self::Const(0, w), _) | (_, Self::Const(0, w)) => Self::Const(0, *w),
                        (Self::Const(1, _), _) => rs,
                        (_, Self::Const(1, _)) => ls,
                        _ => Self::Mul(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::UDiv(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, _)) if *rv != 0 => Self::Const(lv / rv, *lw),
                        _ => Self::UDiv(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::SDiv(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, _)) if *rv != 0 => {
                            let r = sign_extend(*lv, *lw).wrapping_div(sign_extend(*rv, rs.size())).cast_unsigned();
                            Self::Const(r & byte_mask(*lw), *lw)
                        }
                        _ => Self::SDiv(Box::new(ls), Box::new(rs)),
                    }
                }
                _ => unreachable!(),
            }
        }

        fn simplify_bitwise_shift(&self) -> Self {
            match self {
                Self::And(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    if ls == rs { return ls; }
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, _)) => Self::Const(lv & rv, *lw),
                        (Self::Const(0, w), _) | (_, Self::Const(0, w)) => Self::Const(0, *w),
                        (Self::Const(v, w), _) if *v == byte_mask(*w) => rs,
                        (_, Self::Const(v, w)) if *v == byte_mask(*w) => ls,
                        _ => Self::And(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Or(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    if ls == rs { return ls; }
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, _)) => Self::Const(lv | rv, *lw),
                        (Self::Const(0, _), _) => rs,
                        (_, Self::Const(0, _)) => ls,
                        (Self::Const(v, w), _) | (_, Self::Const(v, w)) if *v == byte_mask(*w) => Self::Const(*v, *w),
                        _ => Self::Or(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Xor(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    if ls == rs { return Self::Const(0, ls.size()); }
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, _)) => Self::Const(lv ^ rv, *lw),
                        _ => Self::Xor(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Shl(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, _)) => {
                            let sh = u32::try_from(*rv).unwrap_or(u32::MAX);
                            let r = if sh >= (u32::from(*lw) * 8) { 0 } else { lv << sh };
                            Self::Const(r & byte_mask(*lw), *lw)
                        }
                        (_, Self::Const(0, _)) => ls,
                        _ => Self::Shl(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::LShr(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, _)) => {
                            let sh = u32::try_from(*rv).unwrap_or(u32::MAX);
                            let r = if sh >= 64 { 0 } else { lv >> sh };
                            Self::Const(r & byte_mask(*lw), *lw)
                        }
                        (_, Self::Const(0, _)) => ls,
                        _ => Self::LShr(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::AShr(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, _)) => {
                            let sh = u32::try_from(*rv).unwrap_or(u32::MAX);
                            let sv = sign_extend(*lv, *lw);
                            let r = if sh >= 64 { if sv < 0 { u64::MAX } else { 0 } } else { (sv >> sh).cast_unsigned() };
                            Self::Const(r & byte_mask(*lw), *lw)
                        }
                        (_, Self::Const(0, _)) => ls,
                        _ => Self::AShr(Box::new(ls), Box::new(rs)),
                    }
                }
                _ => unreachable!(),
            }
        }

        fn simplify_ext_ite(&self) -> Self {
            match self {
                Self::ZExt(e, s) => {
                    let es = e.simplify();
                    match &es { Self::Const(v, _) => Self::Const(*v & byte_mask(*s), *s), _ => Self::ZExt(Box::new(es), *s) }
                }
                Self::SExt(e, s) => {
                    let es = e.simplify();
                    match &es {
                        Self::Const(v, ew) => Self::Const(sign_extend(*v, *ew).cast_unsigned() & byte_mask(*s), *s),
                        _ => Self::SExt(Box::new(es), *s),
                    }
                }
                Self::Trunc(e, s) => {
                    let es = e.simplify();
                    match &es { Self::Const(v, _) => Self::Const(*v & byte_mask(*s), *s), _ => Self::Trunc(Box::new(es), *s) }
                }
                Self::Concat(hi, lo) => {
                    let (hs, ls_e) = (hi.simplify(), lo.simplify());
                    match (&hs, &ls_e) {
                        (Self::Const(hv, hw), Self::Const(lv, lw)) => Self::Const((hv << (u32::from(*lw) * 8)) | lv, hw + lw),
                        _ => Self::Concat(Box::new(hs), Box::new(ls_e)),
                    }
                }
                Self::Extract(e, hi, lo) => {
                    let es = e.simplify();
                    match &es {
                        Self::Const(v, _) => {
                            let bits = hi.wrapping_sub(*lo).wrapping_add(1);
                            let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                            Self::Const((v >> lo) & mask, (bits / 8).max(1))
                        }
                        _ => Self::Extract(Box::new(es), *hi, *lo),
                    }
                }
                Self::Load(addr, s) => Self::Load(Box::new(addr.simplify()), *s),
                Self::ITE(cond, t, e) => {
                    let cs = cond.simplify();
                    match &cs {
                        Self::Const(0, _) => e.simplify(),
                        Self::Const(_, _) => t.simplify(),
                        _ => Self::ITE(Box::new(cs), Box::new(t.simplify()), Box::new(e.simplify())),
                    }
                }
                _ => unreachable!(),
            }
        }

        fn simplify_cmp(&self) -> Self {
            match self {
                Self::Eq(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    if ls == rs { return Self::Const(1, 1); }
                    match (&ls, &rs) {
                        (Self::Const(lv, _), Self::Const(rv, _)) => Self::Const(u64::from(lv == rv), 1),
                        _ => Self::Eq(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Ne(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    if ls == rs { return Self::Const(0, 1); }
                    match (&ls, &rs) {
                        (Self::Const(lv, _), Self::Const(rv, _)) => Self::Const(u64::from(lv != rv), 1),
                        _ => Self::Ne(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Ult(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, _), Self::Const(rv, _)) => Self::Const(u64::from(lv < rv), 1),
                        _ => Self::Ult(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Ule(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, _), Self::Const(rv, _)) => Self::Const(u64::from(lv <= rv), 1),
                        _ => Self::Ule(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Ugt(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, _), Self::Const(rv, _)) => Self::Const(u64::from(lv > rv), 1),
                        _ => Self::Ugt(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Uge(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, _), Self::Const(rv, _)) => Self::Const(u64::from(lv >= rv), 1),
                        _ => Self::Uge(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Slt(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, rw)) => Self::Const(u64::from(sign_extend(*lv, *lw) < sign_extend(*rv, *rw)), 1),
                        _ => Self::Slt(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Sle(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, rw)) => Self::Const(u64::from(sign_extend(*lv, *lw) <= sign_extend(*rv, *rw)), 1),
                        _ => Self::Sle(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Sgt(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, rw)) => Self::Const(u64::from(sign_extend(*lv, *lw) > sign_extend(*rv, *rw)), 1),
                        _ => Self::Sgt(Box::new(ls), Box::new(rs)),
                    }
                }
                Self::Sge(a, b) => {
                    let (ls, rs) = (a.simplify(), b.simplify());
                    match (&ls, &rs) {
                        (Self::Const(lv, lw), Self::Const(rv, rw)) => Self::Const(u64::from(sign_extend(*lv, *lw) >= sign_extend(*rv, *rw)), 1),
                        _ => Self::Sge(Box::new(ls), Box::new(rs)),
                    }
                }
                _ => unreachable!(),
            }
        }

        #[must_use]
        pub fn simplify(&self) -> Self {
            match self {
                Self::Const(..) | Self::Symbol(..) => self.clone(),
                Self::Not(..) | Self::Neg(..) => self.simplify_unary(),
                Self::Add(..) | Self::Sub(..) | Self::Mul(..) | Self::UDiv(..) | Self::SDiv(..) => self.simplify_arith(),
                Self::And(..) | Self::Or(..) | Self::Xor(..) | Self::Shl(..) | Self::LShr(..) | Self::AShr(..) => self.simplify_bitwise_shift(),
                Self::ZExt(..) | Self::SExt(..) | Self::Trunc(..) | Self::Concat(..) | Self::Extract(..) | Self::Load(..) | Self::ITE(..) => self.simplify_ext_ite(),
                Self::Eq(..) | Self::Ne(..) | Self::Ult(..) | Self::Ule(..) | Self::Ugt(..) | Self::Uge(..) | Self::Slt(..) | Self::Sle(..) | Self::Sgt(..) | Self::Sge(..) => self.simplify_cmp(),
            }
        }

        #[must_use]
        pub fn substitute(&self, sym: u32, val: &Self) -> Self {
            macro_rules! sub2 {
                ($variant:ident, $a:expr, $b:expr) => {
                    Self::$variant(
                        Box::new($a.substitute(sym, val)),
                        Box::new($b.substitute(sym, val)),
                    )
                };
            }
            match self {
                Self::Symbol(id, _) if *id == sym => val.clone(),
                Self::Const(..) | Self::Symbol(..) => self.clone(),
                Self::Not(e) => Self::Not(Box::new(e.substitute(sym, val))),
                Self::Neg(e) => Self::Neg(Box::new(e.substitute(sym, val))),
                Self::ZExt(e, s) => Self::ZExt(Box::new(e.substitute(sym, val)), *s),
                Self::SExt(e, s) => Self::SExt(Box::new(e.substitute(sym, val)), *s),
                Self::Trunc(e, s) => Self::Trunc(Box::new(e.substitute(sym, val)), *s),
                Self::Extract(e, hi, lo) => {
                    Self::Extract(Box::new(e.substitute(sym, val)), *hi, *lo)
                }
                Self::Load(e, s) => Self::Load(Box::new(e.substitute(sym, val)), *s),
                Self::Add(a, b) => sub2!(Add, a, b),
                Self::Sub(a, b) => sub2!(Sub, a, b),
                Self::Mul(a, b) => sub2!(Mul, a, b),
                Self::UDiv(a, b) => sub2!(UDiv, a, b),
                Self::SDiv(a, b) => sub2!(SDiv, a, b),
                Self::And(a, b) => sub2!(And, a, b),
                Self::Or(a, b) => sub2!(Or, a, b),
                Self::Xor(a, b) => sub2!(Xor, a, b),
                Self::Shl(a, b) => sub2!(Shl, a, b),
                Self::LShr(a, b) => sub2!(LShr, a, b),
                Self::AShr(a, b) => sub2!(AShr, a, b),
                Self::Concat(a, b) => sub2!(Concat, a, b),
                Self::Eq(a, b) => sub2!(Eq, a, b),
                Self::Ne(a, b) => sub2!(Ne, a, b),
                Self::Ult(a, b) => sub2!(Ult, a, b),
                Self::Ule(a, b) => sub2!(Ule, a, b),
                Self::Ugt(a, b) => sub2!(Ugt, a, b),
                Self::Uge(a, b) => sub2!(Uge, a, b),
                Self::Slt(a, b) => sub2!(Slt, a, b),
                Self::Sle(a, b) => sub2!(Sle, a, b),
                Self::Sgt(a, b) => sub2!(Sgt, a, b),
                Self::Sge(a, b) => sub2!(Sge, a, b),
                Self::ITE(c, t, e) => Self::ITE(
                    Box::new(c.substitute(sym, val)),
                    Box::new(t.substitute(sym, val)),
                    Box::new(e.substitute(sym, val)),
                ),
            }
        }

        #[must_use]
        pub fn to_smtlib2(&self) -> String {
            match self {
                Self::Const(v, s) => format!("(_ bv{} {})", v, u32::from(*s) * 8),
                Self::Symbol(id, _) => format!("sym_{id}"),
                Self::Not(e) => format!("(bvnot {})", e.to_smtlib2()),
                Self::Neg(e) => format!("(bvneg {})", e.to_smtlib2()),
                Self::Add(a, b) => format!("(bvadd {} {})", a.to_smtlib2(), b.to_smtlib2()),
                Self::Sub(a, b) => format!("(bvsub {} {})", a.to_smtlib2(), b.to_smtlib2()),
                Self::Mul(a, b) => format!("(bvmul {} {})", a.to_smtlib2(), b.to_smtlib2()),
                Self::UDiv(a, b) => format!("(bvudiv {} {})", a.to_smtlib2(), b.to_smtlib2()),
                Self::SDiv(a, b) => format!("(bvsdiv {} {})", a.to_smtlib2(), b.to_smtlib2()),
                Self::And(a, b) => format!("(bvand {} {})", a.to_smtlib2(), b.to_smtlib2()),
                Self::Or(a, b) => format!("(bvor {} {})", a.to_smtlib2(), b.to_smtlib2()),
                Self::Xor(a, b) => format!("(bvxor {} {})", a.to_smtlib2(), b.to_smtlib2()),
                Self::Shl(a, b) => format!("(bvshl {} {})", a.to_smtlib2(), b.to_smtlib2()),
                Self::LShr(a, b) => format!("(bvlshr {} {})", a.to_smtlib2(), b.to_smtlib2()),
                Self::AShr(a, b) => format!("(bvashr {} {})", a.to_smtlib2(), b.to_smtlib2()),
                Self::ZExt(e, s) => {
                    let ext = (u32::from(*s) * 8).saturating_sub(u32::from(e.size()) * 8);
                    format!("((_ zero_extend {}) {})", ext, e.to_smtlib2())
                }
                Self::SExt(e, s) => {
                    let ext = (u32::from(*s) * 8).saturating_sub(u32::from(e.size()) * 8);
                    format!("((_ sign_extend {}) {})", ext, e.to_smtlib2())
                }
                Self::Trunc(e, s) => {
                    format!("((_ extract {} 0) {})", u32::from(*s) * 8 - 1, e.to_smtlib2())
                }
                Self::Concat(hi, lo) => {
                    format!("(concat {} {})", hi.to_smtlib2(), lo.to_smtlib2())
                }
                Self::Extract(e, hi, lo) => {
                    format!("((_ extract {} {}) {})", hi, lo, e.to_smtlib2())
                }
                Self::Load(addr, _) => format!("(select mem {})", addr.to_smtlib2()),
                Self::ITE(c, t, e) => format!(
                    "(ite (= {} (_ bv1 1)) {} {})",
                    c.to_smtlib2(),
                    t.to_smtlib2(),
                    e.to_smtlib2()
                ),
                Self::Eq(a, b) => format!(
                    "(ite (= {} {}) (_ bv1 1) (_ bv0 1))",
                    a.to_smtlib2(),
                    b.to_smtlib2()
                ),
                Self::Ne(a, b) => format!(
                    "(ite (not (= {} {})) (_ bv1 1) (_ bv0 1))",
                    a.to_smtlib2(),
                    b.to_smtlib2()
                ),
                Self::Ult(a, b) => format!(
                    "(ite (bvult {} {}) (_ bv1 1) (_ bv0 1))",
                    a.to_smtlib2(),
                    b.to_smtlib2()
                ),
                Self::Ule(a, b) => format!(
                    "(ite (bvule {} {}) (_ bv1 1) (_ bv0 1))",
                    a.to_smtlib2(),
                    b.to_smtlib2()
                ),
                Self::Ugt(a, b) => format!(
                    "(ite (bvugt {} {}) (_ bv1 1) (_ bv0 1))",
                    a.to_smtlib2(),
                    b.to_smtlib2()
                ),
                Self::Uge(a, b) => format!(
                    "(ite (bvuge {} {}) (_ bv1 1) (_ bv0 1))",
                    a.to_smtlib2(),
                    b.to_smtlib2()
                ),
                Self::Slt(a, b) => format!(
                    "(ite (bvslt {} {}) (_ bv1 1) (_ bv0 1))",
                    a.to_smtlib2(),
                    b.to_smtlib2()
                ),
                Self::Sle(a, b) => format!(
                    "(ite (bvsle {} {}) (_ bv1 1) (_ bv0 1))",
                    a.to_smtlib2(),
                    b.to_smtlib2()
                ),
                Self::Sgt(a, b) => format!(
                    "(ite (bvsgt {} {}) (_ bv1 1) (_ bv0 1))",
                    a.to_smtlib2(),
                    b.to_smtlib2()
                ),
                Self::Sge(a, b) => format!(
                    "(ite (bvsge {} {}) (_ bv1 1) (_ bv0 1))",
                    a.to_smtlib2(),
                    b.to_smtlib2()
                ),
            }
        }

        #[must_use]
        pub fn to_smtlib2_script(&self) -> String {
            use std::fmt::Write as _;
            let mut syms: Vec<u32> = self.free_symbols().into_iter().collect();
            syms.sort_unstable();
            let mut out = String::from("(set-logic QF_BV)\n");
            for id in &syms {
                writeln!(out, "(declare-fun sym_{id} () (_ BitVec 64))").unwrap();
            }
            writeln!(out, "(assert (= {} (_ bv1 1)))", self.to_smtlib2()).unwrap();
            out.push_str("(check-sat)\n");
            out
        }
    } // impl SymExpr

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // PART 2 Ã¢â‚¬â€ Symbolic Memory
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// A symbolic write with an address that may be symbolic.
    #[derive(Debug, Clone)]
    pub struct SymbolicWrite {
        pub addr: SymExpr,
        pub value: SymExpr,
        pub size: u8,
        pub timestamp: u64,
    }

    /// Named symbolic input metadata.
    #[derive(Debug, Clone)]
    pub struct InputMetadata {
        pub name: String,
        pub symbol_id: u32,
        pub size: u8,
        pub is_taint_source: bool,
    }

    /// Two-layer memory model: concrete-address map + symbolic-address write log.
    #[derive(Debug, Clone)]
    pub struct SymbolicMemory {
        /// Concrete address -> symbolic value.
        pub concrete: BTreeMap<u64, SymExpr>,
        /// Ordered symbolic-address writes.
        pub writes: Vec<SymbolicWrite>,
        /// Monotonic symbol id allocator.
        pub symbol_counter: u32,
        /// Monotonic timestamp for write ordering.
        pub write_clock: u64,
        /// Named input metadata, keyed by symbol id.
        pub inputs: HashMap<u32, InputMetadata>,
    }

    impl SymbolicMemory {
        #[must_use]
        pub fn new() -> Self {
            Self {
                concrete: BTreeMap::new(),
                writes: Vec::new(),
                symbol_counter: 0,
                write_clock: 0,
                inputs: HashMap::new(),
            }
        }

        /// Allocate a fresh unconstrained symbol.
        pub const fn fresh_symbol(&mut self, _name: &str, size: u8) -> SymExpr {
            let id = self.symbol_counter;
            self.symbol_counter += 1;
            SymExpr::Symbol(id, size)
        }

        /// Allocate a named symbolic input (taint source).
        pub fn fresh_input(&mut self, name: &str, size: u8) -> SymExpr {
            let id = self.symbol_counter;
            self.symbol_counter += 1;
            self.inputs.insert(
                id,
                InputMetadata {
                    name: name.to_string(),
                    symbol_id: id,
                    size,
                    is_taint_source: true,
                },
            );
            SymExpr::Symbol(id, size)
        }

        /// Write `value` (of `size` bytes) to `addr`.
        pub fn write(&mut self, addr: SymExpr, value: SymExpr, size: u8) {
            let ts = self.write_clock;
            self.write_clock += 1;
            match addr.as_const() {
                Some(concrete_addr) => {
                    self.concrete.insert(concrete_addr, value);
                }
                None => {
                    self.writes.push(SymbolicWrite {
                        addr,
                        value,
                        size,
                        timestamp: ts,
                    });
                }
            }
        }

        /// Read `size` bytes from `addr`.
        ///
        /// For a concrete address:
        ///   1. Start with the concrete map value (or a fresh symbol for uninitialized).
        ///   2. For each symbolic write that may alias, wrap in ITE.
        ///
        /// For a symbolic address: build an ITE chain over all writes.
        #[must_use]
        pub fn read(&self, addr: &SymExpr, size: u8) -> SymExpr {
            addr.as_const().map_or_else(
                || {
                    // Symbolic address: ITE chain over all known writes.
                    let base = SymExpr::Symbol(u32::MAX, size);
                    self.writes
                        .iter()
                        .chain(std::iter::once(&SymbolicWrite {
                            addr: SymExpr::Const(0, 8),
                            value: base.clone(),
                            size,
                            timestamp: 0,
                        }))
                        .fold(base, |acc, w| {
                            let cond =
                                SymExpr::Eq(Box::new(w.addr.clone()), Box::new(addr.clone()));
                            SymExpr::ITE(Box::new(cond), Box::new(w.value.clone()), Box::new(acc))
                        })
                },
                |concrete_addr| {
                    // Base: concrete map or fresh uninitialized symbol.
                    let base = self
                        .concrete
                        .get(&concrete_addr)
                        .cloned()
                        .unwrap_or_else(|| {
                            let lo32 = u32::try_from(concrete_addr & 0xFFFF_FFFF).unwrap_or(u32::MAX);
                            SymExpr::Symbol(u32::MAX - lo32, size)
                        });
                    // Overlay symbolic writes that may alias.
                    self.writes.iter().fold(base, |acc, w| {
                        if Self::may_alias(&w.addr, addr) {
                            let cond =
                                SymExpr::Eq(Box::new(w.addr.clone()), Box::new(addr.clone()));
                            SymExpr::ITE(Box::new(cond), Box::new(w.value.clone()), Box::new(acc))
                        } else {
                            acc
                        }
                    })
                },
            )
        }

        /// Conservative alias check.
        /// Returns `false` only when both addresses are concrete and differ.
        #[must_use]
        pub const fn may_alias(a: &SymExpr, b: &SymExpr) -> bool {
            match (a.as_const(), b.as_const()) {
                (Some(av), Some(bv)) => av == bv,
                _ => true,
            }
        }

        /// Number of symbolic writes logged.
        #[must_use]
        pub const fn symbolic_write_count(&self) -> usize {
            self.writes.len()
        }

        /// Number of concrete-address entries.
        #[must_use]
        pub fn concrete_entry_count(&self) -> usize {
            self.concrete.len()
        }

        /// Merge another memory into this one (used for state merging).
        pub fn merge(&mut self, other: &Self) {
            for (addr, val) in &other.concrete {
                self.concrete.entry(*addr).or_insert_with(|| val.clone());
            }
            for w in &other.writes {
                self.writes.push(w.clone());
            }
            if other.symbol_counter > self.symbol_counter {
                self.symbol_counter = other.symbol_counter;
            }
        }
    }

    impl Default for SymbolicMemory {
        fn default() -> Self {
            Self::new()
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // PART 3 Ã¢â‚¬â€ Symbolic State
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    static STATE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn alloc_state_id() -> u64 {
        STATE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Per-path execution state for the full symbolic engine.
    #[derive(Debug, Clone)]
    pub struct SxState {
        /// Register file: name -> symbolic expression.
        pub regs: HashMap<String, SymExpr>,
        /// Symbolic memory.
        pub memory: SymbolicMemory,
        /// Path conditions (all must hold simultaneously).
        pub constraints: Vec<SymExpr>,
        /// Current program counter.
        pub pc: u64,
        /// Depth in the fork tree.
        pub depth: u32,
        /// Unique state identifier.
        pub id: u64,
        /// Parent state identifier, if any.
        pub parent_id: Option<u64>,
        /// Sequence of PCs visited (for traces).
        pub path_trace: Vec<u64>,
    }

    impl SxState {
        #[must_use]
        pub fn new(pc: u64) -> Self {
            Self {
                regs: HashMap::new(),
                memory: SymbolicMemory::new(),
                constraints: Vec::new(),
                pc,
                depth: 0,
                id: alloc_state_id(),
                parent_id: None,
                path_trace: Vec::new(),
            }
        }

        /// Fork into (taken, fallthrough) child states.
        #[must_use]
        pub fn fork(&self) -> (Self, Self) {
            let mk = |parent: &Self| -> Self {
                Self {
                    regs: parent.regs.clone(),
                    memory: parent.memory.clone(),
                    constraints: parent.constraints.clone(),
                    pc: parent.pc,
                    depth: parent.depth + 1,
                    id: alloc_state_id(),
                    parent_id: Some(parent.id),
                    path_trace: parent.path_trace.clone(),
                }
            };
            (mk(self), mk(self))
        }

        pub fn add_constraint(&mut self, c: SymExpr) {
            self.constraints.push(c);
        }

        /// Quick unsatisfiability check: any constraint is literally Const(0,_).
        #[must_use]
        pub fn is_trivially_unsat(&self) -> bool {
            self.constraints
                .iter()
                .any(|c| matches!(c, SymExpr::Const(0, _)))
        }

        pub fn set_reg(&mut self, name: &str, val: SymExpr) {
            self.regs.insert(name.to_string(), val);
        }

        /// Read a register; returns a fresh symbolic variable if not set.
        #[must_use]
        pub fn get_reg(&self, name: &str) -> SymExpr {
            self.regs.get(name).cloned().unwrap_or_else(|| {
                // Stable hash: derive symbol id from register name for repeatability.
                let id = name
                    .bytes()
                    .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(u32::from(b)));
                SymExpr::Symbol(id, 8)
            })
        }

        /// Emit all path constraints as a SMT-LIB2 satisfiability query.
        #[must_use]
        pub fn to_smtlib2(&self) -> String {
            use std::fmt::Write as _;
            let mut all_syms: HashSet<u32> = HashSet::new();
            for c in &self.constraints {
                all_syms.extend(c.free_symbols());
            }
            // Also include register symbols.
            for v in self.regs.values() {
                all_syms.extend(v.free_symbols());
            }
            let mut syms: Vec<u32> = all_syms.into_iter().collect();
            syms.sort_unstable();
            let mut out = String::from("(set-logic QF_BV)\n");
            for id in &syms {
                writeln!(out, "(declare-fun sym_{id} () (_ BitVec 64))").unwrap();
            }
            for c in &self.constraints {
                writeln!(out, "(assert (= {} (_ bv1 1)))", c.to_smtlib2()).unwrap();
            }
            out.push_str("(check-sat)\n");
            out
        }

        /// Record the current PC in the trace.
        pub fn record_pc(&mut self) {
            self.path_trace.push(self.pc);
        }

        /// Number of constraints.
        #[must_use]
        pub const fn constraint_count(&self) -> usize {
            self.constraints.len()
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // PART 4 Ã¢â‚¬â€ Path Exploration Engine
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Exploration strategy for the worklist.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ExploreStrategy {
        DFS,
        BFS,
        Random,
        CoverageGuided { target_bbs: HashSet<u64> },
    }

    /// Engine configuration knobs.
    #[derive(Debug, Clone)]
    pub struct ExecConfig {
        pub max_depth: u32,
        pub max_states: usize,
        pub exploration: ExploreStrategy,
        pub solver_timeout_ms: u64,
        pub concretize_loops: bool,
    }

    impl Default for ExecConfig {
        fn default() -> Self {
            Self {
                max_depth: 512,
                max_states: 1024,
                exploration: ExploreStrategy::DFS,
                solver_timeout_ms: 5000,
                concretize_loops: false,
            }
        }
    }

    /// Execution statistics.
    #[derive(Debug, Clone, Default)]
    pub struct ExecStats {
        pub states_explored: u64,
        pub states_forked: u64,
        pub states_pruned: u64,
        pub solver_queries: u64,
        pub bugs_found: u64,
    }

    /// Type of bug discovered.
    #[derive(Debug, Clone)]
    pub enum BugType {
        NullDeref { deref_addr: u64 },
        BufferOverflow { base: u64, offset: u64, size: u64 },
        DivByZero,
        UseAfterFree { addr: u64 },
        FormatStringVuln,
        IntegerOverflow,
        Arbitrary(String),
    }

    /// A discovered bug with reproducing input.
    #[derive(Debug, Clone)]
    pub struct BugReport {
        pub bug_type: BugType,
        pub pc: u64,
        pub description: String,
        pub triggering_input: HashMap<String, u64>,
        pub path_trace: Vec<u64>,
    }

    /// Simplified satisfiability checker (no external solver required).
    ///
    /// Sound (never says UNSAT when SAT) but incomplete.
    #[must_use]
    pub fn check_satisfiable(constraints: &[SymExpr]) -> bool {
        // If any constraint simplifies to Const(0): definitely UNSAT.
        for c in constraints {
            let s = c.simplify();
            if matches!(s, SymExpr::Const(0, _)) {
                return false;
            }
        }
        // Contradiction: Eq(sym, a) and Eq(sym, b) where a != b.
        let mut bindings: HashMap<u32, u64> = HashMap::new();
        for c in constraints {
            if let SymExpr::Eq(a, b) = c {
                if let (SymExpr::Symbol(id, _), SymExpr::Const(v, _)) = (a.as_ref(), b.as_ref()) {
                    if let Some(&prev) = bindings.get(id)
                        && prev != *v {
                            return false;
                        }
                    bindings.insert(*id, *v);
                }
                if let (SymExpr::Const(v, _), SymExpr::Symbol(id, _)) = (a.as_ref(), b.as_ref()) {
                    if let Some(&prev) = bindings.get(id)
                        && prev != *v {
                            return false;
                        }
                    bindings.insert(*id, *v);
                }
            }
        }
        // Ne contradictions.
        for c in constraints {
            if let SymExpr::Ne(a, b) = c
                && let (SymExpr::Symbol(id, _), SymExpr::Const(v, _)) = (a.as_ref(), b.as_ref())
                    && bindings.get(id) == Some(v) {
                        return false;
                    }
        }
        true
    }

    /// Generate a concrete input assignment from a state's constraints.
    /// Uses simple heuristics: bound symbols get their bound value; others cycle
    /// through { 0, 1, `0xDEADBEEF_DEADBEEF` }.
    #[must_use]
    pub fn generate_concrete_input(state: &SxState) -> HashMap<String, u64> {
        let mut bindings: HashMap<u32, u64> = HashMap::new();
        for c in &state.constraints {
            if let SymExpr::Eq(a, b) = c {
                match (a.as_ref(), b.as_ref()) {
                    (SymExpr::Symbol(id, _), SymExpr::Const(v, _))
                    | (SymExpr::Const(v, _), SymExpr::Symbol(id, _)) => {
                        bindings.insert(*id, *v);
                    }
                    _ => {}
                }
            }
        }
        let interesting = [
            0u64,
            1,
            0xDEAD_BEEF_DEAD_BEEF,
            u64::MAX,
            0x4141_4141_4141_4141,
        ];
        let mut result = HashMap::new();
        let mut idx = 0usize;
        for v in state.regs.values() {
            for sym_id in v.free_symbols() {
                if let Some(meta) = state.memory.inputs.get(&sym_id) {
                    let val = bindings
                        .get(&sym_id)
                        .copied()
                        .unwrap_or(interesting[idx % interesting.len()]);
                    result.insert(meta.name.clone(), val);
                    idx += 1;
                }
            }
        }
        result
    }

    /// Worklist-driven symbolic execution engine.
    pub struct SymExecEngine {
        pub worklist: VecDeque<SxState>,
        pub completed: Vec<SxState>,
        pub bugs_found: Vec<BugReport>,
        pub stats: ExecStats,
        pub config: ExecConfig,
        /// Addresses known to be freed (for UAF detection).
        pub freed_addresses: HashSet<u64>,
    }

    impl SymExecEngine {
        #[must_use]
        pub fn new(config: ExecConfig) -> Self {
            Self {
                worklist: VecDeque::new(),
                completed: Vec::new(),
                bugs_found: Vec::new(),
                stats: ExecStats::default(),
                config,
                freed_addresses: HashSet::new(),
            }
        }

        /// Push an initial state.
        pub fn push_initial(&mut self, state: SxState) {
            self.worklist.push_back(state);
        }

        /// Select and remove the next state according to the exploration strategy.
        fn select_next(&mut self) -> Option<SxState> {
            match &self.config.exploration {
                ExploreStrategy::DFS => self.worklist.pop_back(),
                ExploreStrategy::BFS => self.worklist.pop_front(),
                ExploreStrategy::Random => {
                    if self.worklist.is_empty() {
                        return None;
                    }
                    let idx = usize::try_from(self.stats.states_explored).unwrap_or(0) % self.worklist.len();
                    self.worklist.remove(idx)
                }
                ExploreStrategy::CoverageGuided { target_bbs } => {
                    // Prefer states whose PC is in target_bbs first, else FIFO.
                    let targets = target_bbs.clone();
                    let pos = self.worklist.iter().position(|s| targets.contains(&s.pc));
                    if let Some(i) = pos {
                        self.worklist.remove(i)
                    } else {
                        self.worklist.pop_front()
                    }
                }
            }
        }

        /// Fork at a conditional branch and push both children.
        pub fn fork_on_branch(
            &mut self,
            state: &SxState,
            cond: SymExpr,
            taken_pc: u64,
            fallthrough_pc: u64,
        ) {
            self.stats.states_forked += 2;
            let (mut taken, mut fallthrough) = state.fork();
            taken.pc = taken_pc;
            taken.add_constraint(cond.simplify());
            fallthrough.pc = fallthrough_pc;
            fallthrough.add_constraint(SymExpr::Not(Box::new(cond)).simplify());
            if !taken.is_trivially_unsat() && check_satisfiable(&taken.constraints) {
                self.stats.solver_queries += 1;
                if self.worklist.len() < self.config.max_states {
                    self.worklist.push_back(taken);
                } else {
                    self.stats.states_pruned += 1;
                }
            } else {
                self.stats.states_pruned += 1;
            }
            if !fallthrough.is_trivially_unsat() && check_satisfiable(&fallthrough.constraints) {
                self.stats.solver_queries += 1;
                if self.worklist.len() < self.config.max_states {
                    self.worklist.push_back(fallthrough);
                } else {
                    self.stats.states_pruned += 1;
                }
            } else {
                self.stats.states_pruned += 1;
            }
        }

        /// Check a memory access for null dereference or UAF.
        pub fn check_memory_access(&mut self, state: &SxState, addr: &SymExpr, pc: u64) {
            match addr.as_const() {
                Some(0) => {
                    self.bugs_found.push(BugReport {
                        bug_type: BugType::NullDeref { deref_addr: 0 },
                        pc,
                        description: "null pointer dereference".to_string(),
                        triggering_input: generate_concrete_input(state),
                        path_trace: state.path_trace.clone(),
                    });
                    self.stats.bugs_found += 1;
                }
                Some(a) if self.freed_addresses.contains(&a) => {
                    self.bugs_found.push(BugReport {
                        bug_type: BugType::UseAfterFree { addr: a },
                        pc,
                        description: format!("use-after-free at {a:#x}"),
                        triggering_input: generate_concrete_input(state),
                        path_trace: state.path_trace.clone(),
                    });
                    self.stats.bugs_found += 1;
                }
                None
                    // Symbolic pointer Ã¢â‚¬â€ conservatively flag null deref possibility.
                    // Only add once per state.
                    if state.constraints.len() < self.config.max_depth as usize => {
                        self.bugs_found.push(BugReport {
                            bug_type: BugType::NullDeref { deref_addr: 0 },
                            pc,
                            description: "possible null dereference via symbolic pointer"
                                .to_string(),
                            triggering_input: generate_concrete_input(state),
                            path_trace: state.path_trace.clone(),
                        });
                        self.stats.bugs_found += 1;
                    }
                _ => {}
            }
        }

        /// Register that an address was freed.
        pub fn register_free(&mut self, addr: u64) {
            self.freed_addresses.insert(addr);
        }

        /// Get all bug reports.
        #[must_use]
        pub fn bugs(&self) -> &[BugReport] {
            &self.bugs_found
        }

        /// Get statistics snapshot.
        #[must_use]
        pub const fn stats(&self) -> &ExecStats {
            &self.stats
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // PART 5 Ã¢â‚¬â€ Transfer Functions
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Lightweight lifted instruction operation (mirrors rustre-il-lift types).
    #[derive(Debug, Clone)]
    pub enum LlilOp {
        /// `dst_reg` = `eval(src_expr)`
        RegWrite { dst: String, src: LlilExpr },
        /// mem[`addr_expr:size`] = `value_expr`
        MemWrite {
            addr: LlilExpr,
            value: LlilExpr,
            size: u8,
        },
        /// `dst_reg` = mem[`addr_expr:size`]
        MemRead {
            dst: String,
            addr: LlilExpr,
            size: u8,
        },
        /// Unconditional jump to addr.
        Jump { target: LlilExpr },
        /// Conditional branch: if cond != 0, jump to `taken_addr`, else fallthrough.
        CondBranch {
            cond: LlilExpr,
            taken_addr: u64,
            fallthrough_addr: u64,
        },
        /// Function return.
        Return,
        /// System call (number in `LlilExpr`).
        Syscall { nr: LlilExpr },
        /// Intrinsic / unknown operation.
        Intrinsic {
            name: String,
            operands: Vec<LlilExpr>,
        },
        /// Unsigned integer division: dst = lhs / rhs.
        UDiv {
            dst: String,
            lhs: LlilExpr,
            rhs: LlilExpr,
            size: u8,
        },
        /// Signed integer division: dst = lhs / rhs.
        SDiv {
            dst: String,
            lhs: LlilExpr,
            rhs: LlilExpr,
            size: u8,
        },
        /// No operation.
        Nop,
    }

    /// Symbolic-friendly lifted expression type.
    #[derive(Debug, Clone)]
    pub enum LlilExpr {
        Const(u64, u8),
        Reg(String),
        Add(Box<Self>, Box<Self>),
        Sub(Box<Self>, Box<Self>),
        Mul(Box<Self>, Box<Self>),
        UDiv(Box<Self>, Box<Self>),
        SDiv(Box<Self>, Box<Self>),
        And(Box<Self>, Box<Self>),
        Or(Box<Self>, Box<Self>),
        Xor(Box<Self>, Box<Self>),
        Shl(Box<Self>, Box<Self>),
        LShr(Box<Self>, Box<Self>),
        AShr(Box<Self>, Box<Self>),
        Not(Box<Self>),
        Neg(Box<Self>),
        ZExt(Box<Self>, u8),
        SExt(Box<Self>, u8),
        Trunc(Box<Self>, u8),
        Load(Box<Self>, u8),
    }

    /// Evaluate a `LlilExpr` in the context of a `SxState`.
    #[must_use]
    pub fn eval_expr(expr: &LlilExpr, state: &SxState) -> SymExpr {
        match expr {
            LlilExpr::Const(v, s) => SymExpr::Const(*v, *s),
            LlilExpr::Reg(name) => state.get_reg(name),
            LlilExpr::Add(a, b) => {
                SymExpr::Add(Box::new(eval_expr(a, state)), Box::new(eval_expr(b, state)))
                    .simplify()
            }
            LlilExpr::Sub(a, b) => {
                SymExpr::Sub(Box::new(eval_expr(a, state)), Box::new(eval_expr(b, state)))
                    .simplify()
            }
            LlilExpr::Mul(a, b) => {
                SymExpr::Mul(Box::new(eval_expr(a, state)), Box::new(eval_expr(b, state)))
                    .simplify()
            }
            LlilExpr::UDiv(a, b) => {
                SymExpr::UDiv(Box::new(eval_expr(a, state)), Box::new(eval_expr(b, state)))
                    .simplify()
            }
            LlilExpr::SDiv(a, b) => {
                SymExpr::SDiv(Box::new(eval_expr(a, state)), Box::new(eval_expr(b, state)))
                    .simplify()
            }
            LlilExpr::And(a, b) => {
                SymExpr::And(Box::new(eval_expr(a, state)), Box::new(eval_expr(b, state)))
                    .simplify()
            }
            LlilExpr::Or(a, b) => {
                SymExpr::Or(Box::new(eval_expr(a, state)), Box::new(eval_expr(b, state))).simplify()
            }
            LlilExpr::Xor(a, b) => {
                SymExpr::Xor(Box::new(eval_expr(a, state)), Box::new(eval_expr(b, state)))
                    .simplify()
            }
            LlilExpr::Shl(a, b) => {
                SymExpr::Shl(Box::new(eval_expr(a, state)), Box::new(eval_expr(b, state)))
                    .simplify()
            }
            LlilExpr::LShr(a, b) => {
                SymExpr::LShr(Box::new(eval_expr(a, state)), Box::new(eval_expr(b, state)))
                    .simplify()
            }
            LlilExpr::AShr(a, b) => {
                SymExpr::AShr(Box::new(eval_expr(a, state)), Box::new(eval_expr(b, state)))
                    .simplify()
            }
            LlilExpr::Not(e) => SymExpr::Not(Box::new(eval_expr(e, state))).simplify(),
            LlilExpr::Neg(e) => SymExpr::Neg(Box::new(eval_expr(e, state))).simplify(),
            LlilExpr::ZExt(e, s) => SymExpr::ZExt(Box::new(eval_expr(e, state)), *s).simplify(),
            LlilExpr::SExt(e, s) => SymExpr::SExt(Box::new(eval_expr(e, state)), *s).simplify(),
            LlilExpr::Trunc(e, s) => SymExpr::Trunc(Box::new(eval_expr(e, state)), *s).simplify(),
            LlilExpr::Load(addr, s) => {
                let addr_sym = eval_expr(addr, state);
                state.memory.read(&addr_sym, *s)
            }
        }
    }

    /// Result of executing a single `LlilOp`.
    #[derive(Debug, Clone)]
    pub enum LlilStepResult {
        /// Execution continues at the next sequential instruction.
        Continue,
        /// Unconditional jump to a concrete address.
        Jump(u64),
        /// Symbolic jump Ã¢â‚¬â€ address is a `SymExpr` that we could not concretize.
        SymJump(SymExpr),
        /// Fork: (`cond_expr`, `taken_addr`, `fallthrough_addr`).
        Branch {
            cond: SymExpr,
            taken: u64,
            fallthrough: u64,
        },
        /// Function returned.
        Return,
        /// Syscall return value expression (symbolic).
        Syscall(SymExpr),
    }

    /// Execute one `LlilOp` against a mutable `SxState`.
    ///
    /// Returns `LlilStepResult` describing the control-flow outcome.
    /// For side-effecting ops (`RegWrite`, `MemWrite`, `MemRead`) this modifies `state` and returns `Continue`.
    pub fn exec_llil_op(op: &LlilOp, state: &mut SxState) -> LlilStepResult {
        match op {
            LlilOp::Nop => LlilStepResult::Continue,

            LlilOp::RegWrite { dst, src } => {
                let val = eval_expr(src, state);
                state.set_reg(dst, val);
                LlilStepResult::Continue
            }

            LlilOp::MemWrite { addr, value, size } => {
                let addr_sym = eval_expr(addr, state);
                let val_sym = eval_expr(value, state);
                state.memory.write(addr_sym, val_sym, *size);
                LlilStepResult::Continue
            }

            LlilOp::MemRead { dst, addr, size } => {
                let addr_sym = eval_expr(addr, state);
                let val = state.memory.read(&addr_sym, *size);
                state.set_reg(dst, val);
                LlilStepResult::Continue
            }

            LlilOp::Jump { target } => {
                let t = eval_expr(target, state);
                t.as_const().map_or_else(|| LlilStepResult::SymJump(t.clone()), LlilStepResult::Jump)
            }

            LlilOp::CondBranch {
                cond,
                taken_addr,
                fallthrough_addr,
            } => {
                let cond_sym = eval_expr(cond, state).simplify();
                match cond_sym.as_const() {
                    Some(0) => LlilStepResult::Jump(*fallthrough_addr),
                    Some(_) => LlilStepResult::Jump(*taken_addr),
                    None => LlilStepResult::Branch {
                        cond: cond_sym,
                        taken: *taken_addr,
                        fallthrough: *fallthrough_addr,
                    },
                }
            }

            LlilOp::Return => LlilStepResult::Return,

            LlilOp::Syscall { nr } => {
                // Return value is a fresh symbolic (tainted from kernel).
                let _ = eval_expr(nr, state);
                let ret_id = state.memory.symbol_counter;
                state.memory.symbol_counter += 1;
                let ret = SymExpr::Symbol(ret_id, 8);
                state.set_reg("rax", ret.clone());
                LlilStepResult::Syscall(ret)
            }

            LlilOp::Intrinsic {
                name: _,
                operands: _,
            } => {
                // Unknown result Ã¢â‚¬â€ fresh symbol.
                let ret_id = state.memory.symbol_counter;
                state.memory.symbol_counter += 1;
                let ret = SymExpr::Symbol(ret_id, 8);
                state.set_reg("rax", ret);
                LlilStepResult::Continue
            }

            LlilOp::UDiv { dst, lhs, rhs, .. } | LlilOp::SDiv { dst, lhs, rhs, .. } => {
                // Division Ã¢â‚¬â€ produce a fresh symbolic result (may trigger div-by-zero oracle).
                let lhs_sym = eval_expr(lhs, state);
                let rhs_sym = eval_expr(rhs, state);
                let _ = (lhs_sym, rhs_sym);
                let ret_id = state.memory.symbol_counter;
                state.memory.symbol_counter += 1;
                let ret = SymExpr::Symbol(ret_id, 8);
                state.set_reg(dst, ret);
                LlilStepResult::Continue
            }
        }
    }

    /// Run a linear sequence of `LlilOps` against a state until a branching or
    /// terminal op is encountered.  Returns the step result from that op.
    pub fn run_block(ops: &[LlilOp], state: &mut SxState) -> LlilStepResult {
        for op in ops {
            let result = exec_llil_op(op, state);
            match result {
                LlilStepResult::Continue => {}
                other => return other,
            }
        }
        LlilStepResult::Continue
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // PART 6 Ã¢â‚¬â€ Taint Tracking
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// The origin of a taint source.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TaintSource {
        UserInput(String),
        NetworkData,
        FileRead,
        EnvVar,
        Syscall,
    }

    /// A location that should be protected from tainted data.
    #[derive(Debug, Clone)]
    pub enum TaintSink {
        MemWrite(u64),
        Syscall(String),
        Call(u64),
        BranchCondition(u64),
    }

    /// A detected taint flow from source to sink.
    #[derive(Debug, Clone)]
    pub struct TaintFlow {
        pub source_id: u32,
        pub sink_type: String,
        pub at_pc: u64,
        pub via_regs: Vec<String>,
    }

    /// Tracks data-flow taint through registers and memory.
    #[derive(Debug, Clone, Default)]
    pub struct TaintTracker {
        /// Register -> set of taint source symbol ids.
        pub tainted_regs: HashMap<String, HashSet<u32>>,
        /// Concrete memory address -> set of taint source symbol ids.
        pub tainted_mem: BTreeMap<u64, HashSet<u32>>,
        /// Metadata for each taint source symbol id.
        pub sources: HashMap<u32, TaintSource>,
        /// Registered sinks.
        pub sinks: Vec<TaintSink>,
        /// All detected flows.
        pub flows: Vec<TaintFlow>,
    }

    impl TaintTracker {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Register a taint source: associate `source_id` with a source type.
        pub fn register_source(&mut self, id: u32, src: TaintSource) {
            self.sources.insert(id, src);
        }

        /// Mark a register as tainted by `source_id`.
        pub fn mark_tainted(&mut self, reg: &str, source: u32) {
            self.tainted_regs
                .entry(reg.to_string())
                .or_default()
                .insert(source);
        }

        /// Mark a concrete memory address as tainted by `source_id`.
        pub fn mark_mem_tainted(&mut self, addr: u64, source: u32) {
            self.tainted_mem.entry(addr).or_default().insert(source);
        }

        /// Query whether a register is currently tainted.
        #[must_use]
        pub fn is_tainted(&self, reg: &str) -> bool {
            self.tainted_regs.get(reg).is_some_and(|s| !s.is_empty())
        }

        /// Get taint sources flowing into a register.
        #[must_use]
        pub fn taint_sources(&self, reg: &str) -> HashSet<u32> {
            self.tainted_regs.get(reg).cloned().unwrap_or_default()
        }

        /// Propagate taint through a `LlilOp`.
        ///
        /// Rules:
        /// - RegWrite(dst, src): dst taint = `free_symbols(src)` intersected with sources.
        /// - MemWrite(addr, val): if val is tainted, mark mem as tainted.
        /// - MemRead(dst, addr): if mem is tainted, taint dst.
        pub fn propagate_op(&mut self, op: &LlilOp, state: &SxState) {
            match op {
                LlilOp::RegWrite { dst, src } => {
                    let sym = eval_expr(src, state);
                    let syms = sym.free_symbols();
                    let taint: HashSet<u32> = syms
                        .into_iter()
                        .filter(|id| self.sources.contains_key(id))
                        .collect();
                    if taint.is_empty() {
                        self.tainted_regs.remove(dst);
                    } else {
                        self.tainted_regs.insert(dst.clone(), taint);
                    }
                }
                LlilOp::MemWrite { addr, value, .. } => {
                    let val_sym = eval_expr(value, state);
                    let taint: HashSet<u32> = val_sym
                        .free_symbols()
                        .into_iter()
                        .filter(|id| self.sources.contains_key(id))
                        .collect();
                    if let Some(concrete_addr) = eval_expr(addr, state).as_const() {
                        if taint.is_empty() {
                            self.tainted_mem.remove(&concrete_addr);
                        } else {
                            self.tainted_mem.insert(concrete_addr, taint);
                        }
                    }
                }
                LlilOp::MemRead { dst, addr, .. } => {
                    if let Some(concrete_addr) = eval_expr(addr, state).as_const() {
                        if let Some(taint) = self.tainted_mem.get(&concrete_addr) {
                            let t = taint.clone();
                            self.tainted_regs.insert(dst.clone(), t);
                        } else {
                            self.tainted_regs.remove(dst);
                        }
                    }
                }
                LlilOp::CondBranch {
                    cond, taken_addr, ..
                } => {
                    // Tainted branch condition -> flow to BranchCondition sink.
                    let cond_sym = eval_expr(cond, state);
                    let taint: Vec<u32> = cond_sym
                        .free_symbols()
                        .into_iter()
                        .filter(|id| self.sources.contains_key(id))
                        .collect();
                    if !taint.is_empty() {
                        let via: Vec<String> = self.tainted_regs.keys().cloned().collect();
                        for src_id in taint {
                            self.flows.push(TaintFlow {
                                source_id: src_id,
                                sink_type: format!("BranchCondition at {taken_addr:#x}"),
                                at_pc: state.pc,
                                via_regs: via.clone(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        /// Check if a `LlilOp` reaches a registered sink and record any flows.
        pub fn check_sink(&mut self, op: &LlilOp, state: &SxState) {
            match op {
                LlilOp::MemWrite { addr, value, .. } => {
                    let val_sym = eval_expr(value, state);
                    let tainted: Vec<u32> = val_sym
                        .free_symbols()
                        .into_iter()
                        .filter(|id| self.sources.contains_key(id))
                        .collect();
                    if !tainted.is_empty()
                        && let Some(concrete_addr) = eval_expr(addr, state).as_const() {
                            let sink_registered = self.sinks.iter().any(
                                |s| matches!(s, TaintSink::MemWrite(a) if *a == concrete_addr),
                            );
                            if sink_registered {
                                let via: Vec<String> = self.tainted_regs.keys().cloned().collect();
                                for src_id in tainted {
                                    self.flows.push(TaintFlow {
                                        source_id: src_id,
                                        sink_type: format!("MemWrite({concrete_addr:#x})"),
                                        at_pc: state.pc,
                                        via_regs: via.clone(),
                                    });
                                }
                            }
                        }
                }
                LlilOp::Syscall { nr } => {
                    let nr_sym = eval_expr(nr, state);
                    let tainted: Vec<u32> = nr_sym
                        .free_symbols()
                        .into_iter()
                        .filter(|id| self.sources.contains_key(id))
                        .collect();
                    if !tainted.is_empty() {
                        let via: Vec<String> = self.tainted_regs.keys().cloned().collect();
                        for src_id in tainted {
                            self.flows.push(TaintFlow {
                                source_id: src_id,
                                sink_type: "Syscall".to_string(),
                                at_pc: state.pc,
                                via_regs: via.clone(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        /// Register a new sink.
        pub fn add_sink(&mut self, sink: TaintSink) {
            self.sinks.push(sink);
        }

        /// Return all recorded taint flows.
        #[must_use]
        pub fn report(&self) -> Vec<&TaintFlow> {
            self.flows.iter().collect()
        }

        /// Clear all taint state (but keep source/sink registrations).
        pub fn reset(&mut self) {
            self.tainted_regs.clear();
            self.tainted_mem.clear();
            self.flows.clear();
        }

        /// Count of tainted registers currently.
        #[must_use]
        pub fn tainted_reg_count(&self) -> usize {
            self.tainted_regs.len()
        }

        /// Count of tainted memory locations.
        #[must_use]
        pub fn tainted_mem_count(&self) -> usize {
            self.tainted_mem.len()
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // PART 7 Ã¢â‚¬â€ Higher-level Exploration Driver
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// A basic block: an address and its sequence of `LlilOps`.
    #[derive(Debug, Clone)]
    pub struct BasicBlock {
        pub address: u64,
        pub ops: Vec<LlilOp>,
    }

    /// Simple CFG: map from block address to `BasicBlock`.
    #[derive(Debug, Clone, Default)]
    pub struct Cfg {
        pub blocks: HashMap<u64, BasicBlock>,
    }

    impl Cfg {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        pub fn add_block(&mut self, block: BasicBlock) {
            self.blocks.insert(block.address, block);
        }

        #[must_use]
        pub fn get_block(&self, addr: u64) -> Option<&BasicBlock> {
            self.blocks.get(&addr)
        }

        #[must_use]
        pub fn block_count(&self) -> usize {
            self.blocks.len()
        }
    }

    /// Exploration result produced after `explore_cfg`.
    #[derive(Debug, Default)]
    pub struct ExplorationResult {
        pub completed_states: usize,
        pub bugs: Vec<BugReport>,
        pub stats: ExecStats,
        pub covered_blocks: HashSet<u64>,
    }

    /// Explore a CFG starting from `entry_pc` with the given initial state.
    ///
    /// This is the main high-level entry point for the symbolic execution engine.
    #[must_use]
    pub fn explore_cfg(
        cfg: &Cfg,
        entry_pc: u64,
        initial: SxState,
        config: ExecConfig,
    ) -> ExplorationResult {
        let mut engine = SymExecEngine::new(config);
        let mut covered: HashSet<u64> = HashSet::new();

        let mut init = initial;
        init.pc = entry_pc;
        engine.push_initial(init);

        while let Some(mut state) = engine.select_next() {
            engine.stats.states_explored += 1;
            if state.depth >= engine.config.max_depth {
                engine.stats.states_pruned += 1;
                continue;
            }

            state.record_pc();
            covered.insert(state.pc);

            let block = if let Some(b) = cfg.get_block(state.pc) { b.clone() } else {
                // No block at this address Ã¢â‚¬â€ treat as terminal.
                engine.completed.push(state);
                continue;
            };

            let step_result = run_block(&block.ops, &mut state);
            match step_result {
                LlilStepResult::Continue => {
                    // Fall off end of block without explicit branch Ã¢â‚¬â€ complete.
                    engine.completed.push(state);
                }
                LlilStepResult::Jump(target) => {
                    state.pc = target;
                    if engine.worklist.len() < engine.config.max_states {
                        engine.worklist.push_back(state);
                    } else {
                        engine.stats.states_pruned += 1;
                    }
                }
                LlilStepResult::Branch {
                    cond,
                    taken,
                    fallthrough,
                } => {
                    engine.fork_on_branch(&state, cond, taken, fallthrough);
                }
                LlilStepResult::Return => {
                    engine.completed.push(state);
                }
                LlilStepResult::Syscall(_) => {
                    // Continue from next sequential block (state already updated).
                    engine.completed.push(state);
                }
                LlilStepResult::SymJump(_sym) => {
                    // Symbolic jump: treat as terminal for now.
                    engine.completed.push(state);
                }
            }
        }

        ExplorationResult {
            completed_states: engine.completed.len(),
            bugs: engine.bugs_found.clone(),
            stats: engine.stats.clone(),
            covered_blocks: covered,
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // PART 8 Ã¢â‚¬â€ Tests
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[cfg(test)]
    mod tests {
        use super::*;

        // Ã¢â€â‚¬Ã¢â€â‚¬ helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        fn c(v: u64, s: u8) -> SymExpr {
            SymExpr::Const(v, s)
        }
        fn c8(v: u64) -> SymExpr {
            SymExpr::Const(v, 8)
        }
        fn c1(v: u64) -> SymExpr {
            SymExpr::Const(v, 1)
        }
        fn sym(id: u32) -> SymExpr {
            SymExpr::Symbol(id, 8)
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::size Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn size_const() {
            assert_eq!(c8(0).size(), 8);
        }
        #[test]
        fn size_sym() {
            assert_eq!(sym(0).size(), 8);
        }
        #[test]
        fn size_add() {
            assert_eq!(SymExpr::Add(Box::new(c8(1)), Box::new(c8(2))).size(), 8);
        }
        #[test]
        fn size_cmp() {
            assert_eq!(SymExpr::Eq(Box::new(c8(1)), Box::new(c8(1))).size(), 1);
        }
        #[test]
        fn size_zext() {
            assert_eq!(SymExpr::ZExt(Box::new(c(0, 4)), 8).size(), 8);
        }
        #[test]
        fn size_trunc() {
            assert_eq!(SymExpr::Trunc(Box::new(c8(42)), 4).size(), 4);
        }
        #[test]
        fn size_concat() {
            assert_eq!(
                SymExpr::Concat(Box::new(c(0, 4)), Box::new(c(0, 4))).size(),
                8
            );
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::is_concrete Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn is_concrete_const() {
            assert!(c8(99).is_concrete());
        }
        #[test]
        fn is_concrete_sym() {
            assert!(!sym(0).is_concrete());
        }
        #[test]
        fn is_concrete_add_consts() {
            assert!(SymExpr::Add(Box::new(c8(1)), Box::new(c8(2))).is_concrete());
        }
        #[test]
        fn is_concrete_add_sym() {
            assert!(!SymExpr::Add(Box::new(c8(1)), Box::new(sym(0))).is_concrete());
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::free_symbols Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn free_symbols_const() {
            assert!(c8(1).free_symbols().is_empty());
        }
        #[test]
        fn free_symbols_sym() {
            assert!(sym(7).free_symbols().contains(&7));
        }
        #[test]
        fn free_symbols_add() {
            let e = SymExpr::Add(Box::new(sym(3)), Box::new(sym(5)));
            let fs = e.free_symbols();
            assert!(fs.contains(&3) && fs.contains(&5));
        }
        #[test]
        fn free_symbols_ite() {
            let e = SymExpr::ITE(Box::new(sym(0)), Box::new(sym(1)), Box::new(sym(2)));
            let fs = e.free_symbols();
            assert!(fs.contains(&0) && fs.contains(&1) && fs.contains(&2));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::as_const Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn as_const_some() {
            assert_eq!(c8(42).as_const(), Some(42));
        }
        #[test]
        fn as_const_none() {
            assert_eq!(sym(0).as_const(), None);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::evaluate_concrete Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn eval_add_concrete() {
            let e = SymExpr::Add(Box::new(c8(3)), Box::new(c8(4)));
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(7));
        }
        #[test]
        fn eval_mul_concrete() {
            let e = SymExpr::Mul(Box::new(c8(6)), Box::new(c8(7)));
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(42));
        }
        #[test]
        fn eval_sym_bound() {
            let e = SymExpr::Add(Box::new(sym(0)), Box::new(c8(10)));
            let mut m = HashMap::new();
            m.insert(0u32, 5u64);
            assert_eq!(e.evaluate_concrete(&m), Some(15));
        }
        #[test]
        fn eval_sym_unbound() {
            let e = SymExpr::Add(Box::new(sym(0)), Box::new(c8(10)));
            assert_eq!(e.evaluate_concrete(&HashMap::new()), None);
        }
        #[test]
        fn eval_xor_self() {
            let e = SymExpr::Xor(Box::new(c8(0xAB)), Box::new(c8(0xAB)));
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(0));
        }
        #[test]
        fn eval_eq_true() {
            let e = SymExpr::Eq(Box::new(c8(5)), Box::new(c8(5)));
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(1));
        }
        #[test]
        fn eval_eq_false() {
            let e = SymExpr::Eq(Box::new(c8(5)), Box::new(c8(6)));
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(0));
        }
        #[test]
        fn eval_not() {
            let e = SymExpr::Not(Box::new(c(0, 1)));
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(0xFF));
        }
        #[test]
        fn eval_neg() {
            let e = SymExpr::Neg(Box::new(c(1, 8)));
            let result = e.evaluate_concrete(&HashMap::new()).unwrap();
            assert_eq!(result, u64::MAX); // -1 as u64 (masked to 8 bytes)
        }
        #[test]
        fn eval_shl() {
            let e = SymExpr::Shl(Box::new(c(1, 8)), Box::new(c(4, 8)));
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(16));
        }
        #[test]
        fn eval_lshr() {
            let e = SymExpr::LShr(Box::new(c(16, 8)), Box::new(c(4, 8)));
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(1));
        }
        #[test]
        fn eval_zext() {
            let e = SymExpr::ZExt(Box::new(c(0xFF, 1)), 8);
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(0xFF));
        }
        #[test]
        fn eval_trunc() {
            let e = SymExpr::Trunc(Box::new(c(0x1122_3344_5566_7788, 8)), 4);
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(0x5566_7788));
        }
        #[test]
        fn eval_slt_true() {
            let e = SymExpr::Slt(Box::new(c(u64::MAX, 8)), Box::new(c(0, 8))); // -1 < 0
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(1));
        }
        #[test]
        fn eval_udiv() {
            let e = SymExpr::UDiv(Box::new(c(10, 8)), Box::new(c(3, 8)));
            assert_eq!(e.evaluate_concrete(&HashMap::new()), Some(3));
        }
        #[test]
        fn eval_udiv_zero_returns_none() {
            let e = SymExpr::UDiv(Box::new(c(10, 8)), Box::new(c(0, 8)));
            assert_eq!(e.evaluate_concrete(&HashMap::new()), None);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::simplify Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn simplify_add_consts() {
            assert_eq!(
                SymExpr::Add(Box::new(c8(10)), Box::new(c8(32))).simplify(),
                c8(42)
            );
        }
        #[test]
        fn simplify_add_zero_r() {
            assert_eq!(
                SymExpr::Add(Box::new(sym(0)), Box::new(c8(0))).simplify(),
                sym(0)
            );
        }
        #[test]
        fn simplify_add_zero_l() {
            assert_eq!(
                SymExpr::Add(Box::new(c8(0)), Box::new(sym(1))).simplify(),
                sym(1)
            );
        }
        #[test]
        fn simplify_sub_self() {
            assert_eq!(
                SymExpr::Sub(Box::new(sym(0)), Box::new(sym(0))).simplify(),
                c8(0)
            );
        }
        #[test]
        fn simplify_mul_zero() {
            assert_eq!(
                SymExpr::Mul(Box::new(sym(0)), Box::new(c8(0)))
                    .simplify()
                    .as_const(),
                Some(0)
            );
        }
        #[test]
        fn simplify_mul_one() {
            assert_eq!(
                SymExpr::Mul(Box::new(sym(3)), Box::new(c8(1))).simplify(),
                sym(3)
            );
        }
        #[test]
        fn simplify_and_zero() {
            assert_eq!(
                SymExpr::And(Box::new(sym(0)), Box::new(c8(0)))
                    .simplify()
                    .as_const(),
                Some(0)
            );
        }
        #[test]
        fn simplify_and_self() {
            assert_eq!(
                SymExpr::And(Box::new(sym(2)), Box::new(sym(2))).simplify(),
                sym(2)
            );
        }
        #[test]
        fn simplify_or_zero() {
            assert_eq!(
                SymExpr::Or(Box::new(sym(1)), Box::new(c8(0))).simplify(),
                sym(1)
            );
        }
        #[test]
        fn simplify_or_self() {
            assert_eq!(
                SymExpr::Or(Box::new(sym(7)), Box::new(sym(7))).simplify(),
                sym(7)
            );
        }
        #[test]
        fn simplify_xor_self() {
            assert_eq!(
                SymExpr::Xor(Box::new(sym(4)), Box::new(sym(4))).simplify(),
                c8(0)
            );
        }
        #[test]
        fn simplify_not_const() {
            assert_eq!(SymExpr::Not(Box::new(c(0, 1))).simplify(), c(0xFF, 1));
        }
        #[test]
        fn simplify_double_not() {
            let e = SymExpr::Not(Box::new(SymExpr::Not(Box::new(sym(9)))));
            assert_eq!(e.simplify(), sym(9));
        }
        #[test]
        fn simplify_ite_true() {
            let e = SymExpr::ITE(Box::new(c1(1)), Box::new(c8(42)), Box::new(c8(0)));
            assert_eq!(e.simplify(), c8(42));
        }
        #[test]
        fn simplify_ite_false() {
            let e = SymExpr::ITE(Box::new(c1(0)), Box::new(c8(99)), Box::new(c8(7)));
            assert_eq!(e.simplify(), c8(7));
        }
        #[test]
        fn simplify_eq_same() {
            assert_eq!(
                SymExpr::Eq(Box::new(sym(0)), Box::new(sym(0))).simplify(),
                c1(1)
            );
        }
        #[test]
        fn simplify_ne_same() {
            assert_eq!(
                SymExpr::Ne(Box::new(sym(0)), Box::new(sym(0))).simplify(),
                c1(0)
            );
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::substitute Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn substitute_sym() {
            let e = SymExpr::Add(Box::new(sym(0)), Box::new(c8(10)));
            let result = e.substitute(0, &c8(5));
            assert_eq!(result.simplify(), c8(15));
        }
        #[test]
        fn substitute_no_match() {
            let e = sym(1);
            assert_eq!(e.substitute(0, &c8(99)), sym(1));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExpr::to_smtlib2 Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn smtlib2_const() {
            let s = c8(42).to_smtlib2();
            assert!(s.contains("bv42") && s.contains("64"));
        }
        #[test]
        fn smtlib2_sym() {
            let s = sym(3).to_smtlib2();
            assert_eq!(s, "sym_3");
        }
        #[test]
        fn smtlib2_add() {
            let s = SymExpr::Add(Box::new(c8(1)), Box::new(c8(2))).to_smtlib2();
            assert!(s.contains("bvadd"));
        }
        #[test]
        fn smtlib2_script_contains_declare() {
            let e = SymExpr::Add(Box::new(sym(0)), Box::new(sym(1)));
            let script = e.to_smtlib2_script();
            assert!(script.contains("declare-fun sym_0"));
            assert!(script.contains("declare-fun sym_1"));
            assert!(script.contains("check-sat"));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymbolicMemory Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn mem_write_concrete_read_back() {
            let mut m = SymbolicMemory::new();
            m.write(c8(0x1000), c8(42), 8);
            let v = m.read(&c8(0x1000), 8);
            assert_eq!(v, c8(42));
        }
        #[test]
        fn mem_read_uninit_returns_symbol() {
            let m = SymbolicMemory::new();
            let v = m.read(&c8(0x2000), 8);
            assert!(matches!(v, SymExpr::Symbol(..)));
        }
        #[test]
        fn mem_symbolic_write_creates_ite() {
            let mut m = SymbolicMemory::new();
            m.write(sym(0), c8(99), 8);
            let v = m.read(&c8(0x1000), 8);
            assert!(matches!(v, SymExpr::ITE(..) | SymExpr::Symbol(..)));
        }
        #[test]
        fn mem_fresh_symbol_increments_counter() {
            let mut m = SymbolicMemory::new();
            let s0 = m.fresh_symbol("a", 8);
            let s1 = m.fresh_symbol("b", 8);
            assert_ne!(s0, s1);
        }
        #[test]
        fn mem_fresh_input_is_taint_source() {
            let mut m = SymbolicMemory::new();
            let inp = m.fresh_input("user_data", 8);
            if let SymExpr::Symbol(id, _) = inp {
                assert!(m.inputs.contains_key(&id));
                assert!(m.inputs[&id].is_taint_source);
            } else {
                panic!("expected Symbol");
            }
        }
        #[test]
        fn mem_may_alias_concrete_same() {
            assert!(SymbolicMemory::may_alias(&c8(0x100), &c8(0x100)));
        }
        #[test]
        fn mem_may_alias_concrete_diff() {
            assert!(!SymbolicMemory::may_alias(&c8(0x100), &c8(0x200)));
        }
        #[test]
        fn mem_may_alias_symbolic() {
            assert!(SymbolicMemory::may_alias(&sym(0), &c8(0x100)));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SxState Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn state_new_and_pc() {
            let s = SxState::new(0x4000);
            assert_eq!(s.pc, 0x4000);
            assert_eq!(s.depth, 0);
            assert!(s.constraints.is_empty());
        }
        #[test]
        fn state_fork_depth_increments() {
            let s = SxState::new(0x1000);
            let (a, b) = s.fork();
            assert_eq!(a.depth, 1);
            assert_eq!(b.depth, 1);
        }
        #[test]
        fn state_set_get_reg() {
            let mut s = SxState::new(0);
            s.set_reg("rax", c8(42));
            assert_eq!(s.get_reg("rax"), c8(42));
        }
        #[test]
        fn state_get_unset_reg_is_symbol() {
            let s = SxState::new(0);
            let v = s.get_reg("rbx");
            assert!(matches!(v, SymExpr::Symbol(..)));
        }
        #[test]
        fn state_add_constraint() {
            let mut s = SxState::new(0);
            s.add_constraint(c1(1));
            assert_eq!(s.constraint_count(), 1);
        }
        #[test]
        fn state_trivially_unsat_false_constraint() {
            let mut s = SxState::new(0);
            s.add_constraint(c1(0));
            assert!(s.is_trivially_unsat());
        }
        #[test]
        fn state_trivially_unsat_no_constraint() {
            let s = SxState::new(0);
            assert!(!s.is_trivially_unsat());
        }
        #[test]
        fn state_smtlib2_has_check_sat() {
            let mut s = SxState::new(0);
            s.add_constraint(SymExpr::Eq(Box::new(sym(0)), Box::new(c8(42))));
            let script = s.to_smtlib2();
            assert!(script.contains("check-sat"));
            assert!(script.contains("declare-fun sym_0"));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ check_satisfiable Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn sat_no_constraints() {
            assert!(check_satisfiable(&[]));
        }
        #[test]
        fn sat_true_constraint() {
            assert!(check_satisfiable(&[c1(1)]));
        }
        #[test]
        fn unsat_false_constraint() {
            assert!(!check_satisfiable(&[c1(0)]));
        }
        #[test]
        fn sat_eq_binding() {
            let c = SymExpr::Eq(Box::new(sym(0)), Box::new(c8(5)));
            assert!(check_satisfiable(&[c]));
        }
        #[test]
        fn unsat_contradictory_eq() {
            let c1_e = SymExpr::Eq(Box::new(sym(0)), Box::new(c8(5)));
            let c2_e = SymExpr::Eq(Box::new(sym(0)), Box::new(c8(6)));
            assert!(!check_satisfiable(&[c1_e, c2_e]));
        }
        #[test]
        fn unsat_eq_ne_same() {
            let c1_e = SymExpr::Eq(Box::new(sym(0)), Box::new(c8(5)));
            let c2_e = SymExpr::Ne(Box::new(sym(0)), Box::new(c8(5)));
            assert!(!check_satisfiable(&[c1_e, c2_e]));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymExecEngine Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn engine_new_empty_worklist() {
            let e = SymExecEngine::new(ExecConfig::default());
            assert!(e.worklist.is_empty());
            assert!(e.bugs_found.is_empty());
        }
        #[test]
        fn engine_push_initial() {
            let mut e = SymExecEngine::new(ExecConfig::default());
            e.push_initial(SxState::new(0x1000));
            assert_eq!(e.worklist.len(), 1);
        }
        #[test]
        fn engine_fork_symbolic_branch_creates_two_states() {
            let mut e = SymExecEngine::new(ExecConfig::default());
            let state = SxState::new(0x1000);
            e.fork_on_branch(&state, sym(0), 0x1004, 0x2000);
            assert_eq!(e.worklist.len(), 2);
        }
        #[test]
        fn engine_fork_concrete_true_only_taken() {
            let mut e = SymExecEngine::new(ExecConfig::default());
            let state = SxState::new(0x1000);
            e.fork_on_branch(&state, c1(1), 0x4000, 0x8000);
            // taken: cond=true, fallthrough pruned
            let pcs: Vec<u64> = e.worklist.iter().map(|s| s.pc).collect();
            assert!(pcs.contains(&0x4000));
            assert!(!pcs.contains(&0x8000));
        }
        #[test]
        fn engine_fork_concrete_false_only_fallthrough() {
            let mut e = SymExecEngine::new(ExecConfig::default());
            let state = SxState::new(0x1000);
            e.fork_on_branch(&state, c1(0), 0x4000, 0x8000);
            let pcs: Vec<u64> = e.worklist.iter().map(|s| s.pc).collect();
            assert!(!pcs.contains(&0x4000));
            assert!(pcs.contains(&0x8000));
        }
        #[test]
        fn engine_null_deref_bug_detected() {
            let mut e = SymExecEngine::new(ExecConfig::default());
            let state = SxState::new(0x1000);
            e.check_memory_access(&state, &c8(0), 0x1000);
            assert_eq!(e.bugs_found.len(), 1);
            assert!(matches!(
                e.bugs_found[0].bug_type,
                BugType::NullDeref { .. }
            ));
        }
        #[test]
        fn engine_uaf_detected() {
            let mut e = SymExecEngine::new(ExecConfig::default());
            e.register_free(0xDEAD_BEEF);
            let state = SxState::new(0x1000);
            e.check_memory_access(&state, &c8(0xDEAD_BEEF), 0x1000);
            assert_eq!(e.bugs_found.len(), 1);
            assert!(matches!(
                e.bugs_found[0].bug_type,
                BugType::UseAfterFree { .. }
            ));
        }
        #[test]
        fn engine_stats_updated() {
            let mut e = SymExecEngine::new(ExecConfig::default());
            let state = SxState::new(0x1000);
            e.fork_on_branch(&state, sym(0), 0x1004, 0x2000);
            assert_eq!(e.stats.states_forked, 2);
            assert_eq!(e.stats.solver_queries, 2);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ eval_expr Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn eval_const_expr() {
            let s = SxState::new(0);
            let r = eval_expr(&LlilExpr::Const(42, 8), &s);
            assert_eq!(r, c8(42));
        }
        #[test]
        fn eval_reg_expr() {
            let mut s = SxState::new(0);
            s.set_reg("rax", c8(99));
            let r = eval_expr(&LlilExpr::Reg("rax".to_string()), &s);
            assert_eq!(r, c8(99));
        }
        #[test]
        fn eval_add_expr() {
            let s = SxState::new(0);
            let e = LlilExpr::Add(
                Box::new(LlilExpr::Const(3, 8)),
                Box::new(LlilExpr::Const(4, 8)),
            );
            assert_eq!(eval_expr(&e, &s), c8(7));
        }
        #[test]
        fn eval_not_expr() {
            let s = SxState::new(0);
            let e = LlilExpr::Not(Box::new(LlilExpr::Const(0, 1)));
            assert_eq!(eval_expr(&e, &s), c(0xFF, 1));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ exec_llil_op Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn exec_reg_write() {
            let mut s = SxState::new(0x1000);
            let op = LlilOp::RegWrite {
                dst: "rax".to_string(),
                src: LlilExpr::Const(77, 8),
            };
            let r = exec_llil_op(&op, &mut s);
            assert!(matches!(r, LlilStepResult::Continue));
            assert_eq!(s.get_reg("rax"), c8(77));
        }
        #[test]
        fn exec_mem_write_read() {
            let mut s = SxState::new(0);
            let w = LlilOp::MemWrite {
                addr: LlilExpr::Const(0x8000, 8),
                value: LlilExpr::Const(0xBEEF, 8),
                size: 8,
            };
            exec_llil_op(&w, &mut s);
            let r = LlilOp::MemRead {
                dst: "rbx".to_string(),
                addr: LlilExpr::Const(0x8000, 8),
                size: 8,
            };
            exec_llil_op(&r, &mut s);
            assert_eq!(s.get_reg("rbx"), c8(0xBEEF));
        }
        #[test]
        fn exec_cond_branch_concrete_true() {
            let mut s = SxState::new(0x1000);
            let op = LlilOp::CondBranch {
                cond: LlilExpr::Const(1, 1),
                taken_addr: 0x2000,
                fallthrough_addr: 0x3000,
            };
            let r = exec_llil_op(&op, &mut s);
            assert!(matches!(r, LlilStepResult::Jump(0x2000)));
        }
        #[test]
        fn exec_cond_branch_concrete_false() {
            let mut s = SxState::new(0x1000);
            let op = LlilOp::CondBranch {
                cond: LlilExpr::Const(0, 1),
                taken_addr: 0x2000,
                fallthrough_addr: 0x3000,
            };
            let r = exec_llil_op(&op, &mut s);
            assert!(matches!(r, LlilStepResult::Jump(0x3000)));
        }
        #[test]
        fn exec_cond_branch_symbolic() {
            let mut s = SxState::new(0x1000);
            let op = LlilOp::CondBranch {
                cond: LlilExpr::Reg("rflags".to_string()),
                taken_addr: 0x2000,
                fallthrough_addr: 0x3000,
            };
            let r = exec_llil_op(&op, &mut s);
            assert!(matches!(
                r,
                LlilStepResult::Branch {
                    taken: 0x2000,
                    fallthrough: 0x3000,
                    ..
                }
            ));
        }
        #[test]
        fn exec_return() {
            let mut s = SxState::new(0);
            let r = exec_llil_op(&LlilOp::Return, &mut s);
            assert!(matches!(r, LlilStepResult::Return));
        }
        #[test]
        fn exec_nop() {
            let mut s = SxState::new(0);
            let r = exec_llil_op(&LlilOp::Nop, &mut s);
            assert!(matches!(r, LlilStepResult::Continue));
        }
        #[test]
        fn exec_syscall_returns_symbol() {
            let mut s = SxState::new(0);
            let op = LlilOp::Syscall {
                nr: LlilExpr::Const(1, 8),
            };
            let r = exec_llil_op(&op, &mut s);
            assert!(matches!(r, LlilStepResult::Syscall(_)));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ TaintTracker Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn taint_mark_and_check() {
            let mut t = TaintTracker::new();
            t.register_source(0, TaintSource::UserInput("stdin".to_string()));
            t.mark_tainted("rdi", 0);
            assert!(t.is_tainted("rdi"));
            assert!(!t.is_tainted("rsi"));
        }
        #[test]
        fn taint_propagate_reg_write() {
            let mut t = TaintTracker::new();
            t.register_source(0, TaintSource::UserInput("x".to_string()));
            let mut state = SxState::new(0);
            // Put a symbolic input in rdi.
            state.set_reg("rdi", SymExpr::Symbol(0, 8));
            t.mark_tainted("rdi", 0);
            let op = LlilOp::RegWrite {
                dst: "rax".to_string(),
                src: LlilExpr::Reg("rdi".to_string()),
            };
            t.propagate_op(&op, &state);
            assert!(t.is_tainted("rax"));
        }
        #[test]
        fn taint_clean_write_clears() {
            let mut t = TaintTracker::new();
            t.register_source(0, TaintSource::UserInput("x".to_string()));
            t.mark_tainted("rax", 0);
            let state = SxState::new(0);
            let op = LlilOp::RegWrite {
                dst: "rax".to_string(),
                src: LlilExpr::Const(42, 8),
            };
            t.propagate_op(&op, &state);
            assert!(!t.is_tainted("rax"));
        }
        #[test]
        fn taint_mem_write_marks_memory() {
            let mut t = TaintTracker::new();
            t.register_source(0, TaintSource::NetworkData);
            let mut state = SxState::new(0);
            state.set_reg("rsi", SymExpr::Symbol(0, 8));
            t.mark_tainted("rsi", 0);
            let op = LlilOp::MemWrite {
                addr: LlilExpr::Const(0x5000, 8),
                value: LlilExpr::Reg("rsi".to_string()),
                size: 8,
            };
            t.propagate_op(&op, &state);
            let empty_set = HashSet::new();
            assert!(
                !t.tainted_mem
                    .get(&0x5000)
                    .unwrap_or(&empty_set)
                    .is_empty()
            );
        }
        #[test]
        fn taint_report_empty_initially() {
            let t = TaintTracker::new();
            assert!(t.report().is_empty());
        }
        #[test]
        fn taint_reset_clears_state() {
            let mut t = TaintTracker::new();
            t.register_source(0, TaintSource::EnvVar);
            t.mark_tainted("rcx", 0);
            t.reset();
            assert!(!t.is_tainted("rcx"));
            assert!(t.report().is_empty());
        }
        #[test]
        fn taint_add_sink_and_count() {
            let mut t = TaintTracker::new();
            t.add_sink(TaintSink::MemWrite(0xDEAD));
            assert_eq!(t.sinks.len(), 1);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Cfg / explore_cfg Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn cfg_add_get_block() {
            let mut cfg = Cfg::new();
            cfg.add_block(BasicBlock {
                address: 0x1000,
                ops: vec![LlilOp::Nop],
            });
            assert!(cfg.get_block(0x1000).is_some());
            assert!(cfg.get_block(0x2000).is_none());
            assert_eq!(cfg.block_count(), 1);
        }
        #[test]
        fn explore_cfg_single_ret_block() {
            let mut cfg = Cfg::new();
            cfg.add_block(BasicBlock {
                address: 0x1000,
                ops: vec![LlilOp::Return],
            });
            let state = SxState::new(0x1000);
            let result = explore_cfg(&cfg, 0x1000, state, ExecConfig::default());
            assert_eq!(result.completed_states, 1);
            assert!(result.bugs.is_empty());
            assert!(result.covered_blocks.contains(&0x1000));
        }
        #[test]
        fn explore_cfg_linear_two_blocks() {
            let mut cfg = Cfg::new();
            cfg.add_block(BasicBlock {
                address: 0x1000,
                ops: vec![
                    LlilOp::RegWrite {
                        dst: "rax".to_string(),
                        src: LlilExpr::Const(1, 8),
                    },
                    LlilOp::Jump {
                        target: LlilExpr::Const(0x2000, 8),
                    },
                ],
            });
            cfg.add_block(BasicBlock {
                address: 0x2000,
                ops: vec![LlilOp::Return],
            });
            let state = SxState::new(0x1000);
            let result = explore_cfg(&cfg, 0x1000, state, ExecConfig::default());
            assert_eq!(result.completed_states, 1);
            assert!(result.covered_blocks.contains(&0x1000));
            assert!(result.covered_blocks.contains(&0x2000));
        }
        #[test]
        fn explore_cfg_branch_both_paths() {
            let mut cfg = Cfg::new();
            cfg.add_block(BasicBlock {
                address: 0x1000,
                ops: vec![LlilOp::CondBranch {
                    cond: LlilExpr::Reg("rflags".to_string()),
                    taken_addr: 0x2000,
                    fallthrough_addr: 0x3000,
                }],
            });
            cfg.add_block(BasicBlock {
                address: 0x2000,
                ops: vec![LlilOp::Return],
            });
            cfg.add_block(BasicBlock {
                address: 0x3000,
                ops: vec![LlilOp::Return],
            });
            let state = SxState::new(0x1000);
            let result = explore_cfg(&cfg, 0x1000, state, ExecConfig::default());
            // Both branches should complete.
            assert_eq!(result.completed_states, 2);
            assert!(
                result.covered_blocks.contains(&0x2000) || result.covered_blocks.contains(&0x3000)
            );
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ generate_concrete_input Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn generate_input_bound_sym() {
            let mut state = SxState::new(0);
            let inp = state.memory.fresh_input("user_arg", 8);
            if let SymExpr::Symbol(id, _) = &inp {
                state.set_reg("rdi", inp.clone());
                state.add_constraint(SymExpr::Eq(
                    Box::new(SymExpr::Symbol(*id, 8)),
                    Box::new(c8(0x41)),
                ));
            }
            let inputs = generate_concrete_input(&state);
            assert!(inputs.contains_key("user_arg"));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ byte_mask helper Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn byte_mask_1() {
            assert_eq!(byte_mask(1), 0xFF);
        }
        #[test]
        fn byte_mask_4() {
            assert_eq!(byte_mask(4), 0xFFFF_FFFF);
        }
        #[test]
        fn byte_mask_8() {
            assert_eq!(byte_mask(8), u64::MAX);
        }
        #[test]
        fn byte_mask_0() {
            assert_eq!(byte_mask(0), 0);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ sign_extend helper Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn sign_extend_neg1_byte() {
            assert_eq!(sign_extend(0xFF, 1), -1i64);
        }
        #[test]
        fn sign_extend_pos() {
            assert_eq!(sign_extend(0x7F, 1), 127i64);
        }
    }
} // mod full_symex

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// SUPPLEMENTAL Ã¢â‚¬â€ Extended Symbolic Execution Components
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Extended analysis components that build on the core engine.
pub mod analysis {

    use super::full_symex::{SymExpr, SxState, SymbolicMemory, LlilOp, LlilExpr};
    use std::collections::{HashMap, HashSet};

    /// Re-exports of additional collections used by callers building extended
    /// analyses (BFS frontiers, ordered constraint maps, Ã¢â‚¬Â¦) on top of this module.
    pub use std::collections::{BTreeMap, VecDeque};

    // Ã¢â€â‚¬Ã¢â€â‚¬ Constraint Simplification Pass Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Apply repeated simplification to a constraint set until fixpoint.
    #[must_use]
    pub fn simplify_constraints(constraints: &[SymExpr]) -> Vec<SymExpr> {
        constraints
            .iter()
            .map(super::full_symex::SymExpr::simplify)
            .filter(|c| !matches!(c, SymExpr::Const(1, _))) // trivially true Ã¢â‚¬â€ drop
            .collect()
    }

    /// Check if a set of constraints contains an obvious contradiction.
    #[must_use]
    pub fn has_contradiction(constraints: &[SymExpr]) -> bool {
        // Collect equality bindings.
        let mut eq_map: HashMap<u32, Vec<u64>> = HashMap::new();
        for c in constraints {
            match c.simplify() {
                SymExpr::Const(0, _) => return true,
                SymExpr::Eq(a, b) => match (a.as_ref(), b.as_ref()) {
                    (SymExpr::Symbol(id, _), SymExpr::Const(v, _))
                    | (SymExpr::Const(v, _), SymExpr::Symbol(id, _)) => {
                        eq_map.entry(*id).or_default().push(*v);
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        // Contradiction: sym bound to two different values.
        for vals in eq_map.values() {
            let first = vals[0];
            if vals.iter().any(|&v| v != first) {
                return true;
            }
        }
        false
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Loop Bounding Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Loop-bound analysis: detect back-edges in a CFG and annotate them.
    #[derive(Debug, Clone, Default)]
    pub struct LoopBoundAnalysis {
        /// Back-edge source -> target (loop header).
        pub back_edges: HashMap<u64, u64>,
        /// Loop iteration count per header (conservative estimate).
        pub bounds: HashMap<u64, u32>,
        /// Default bound applied when no concrete bound can be inferred.
        pub default_bound: u32,
    }

    impl LoopBoundAnalysis {
        #[must_use]
        pub fn new(default_bound: u32) -> Self {
            Self {
                back_edges: HashMap::new(),
                bounds: HashMap::new(),
                default_bound,
            }
        }

        /// Register a known back-edge.
        pub fn add_back_edge(&mut self, from: u64, to: u64) {
            self.back_edges.insert(from, to);
        }

        /// Set a concrete iteration bound for a loop header.
        pub fn set_bound(&mut self, header: u64, bound: u32) {
            self.bounds.insert(header, bound);
        }

        /// Get the bound for a loop header (or `default_bound`).
        #[must_use]
        pub fn get_bound(&self, header: u64) -> u32 {
            self.bounds
                .get(&header)
                .copied()
                .unwrap_or(self.default_bound)
        }

        /// Check whether `pc` is a loop header.
        #[must_use]
        pub fn is_loop_header(&self, pc: u64) -> bool {
            self.back_edges.values().any(|&h| h == pc)
        }

        /// Summary of detected loops.
        #[must_use]
        pub fn loop_count(&self) -> usize {
            self.back_edges.len()
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ State Merging Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Attempt to merge two states at the same PC into one state.
    ///
    /// State merging reduces path explosion at join points by combining two
    /// states S1 and S2 into a single merged state SM:
    ///   - For each register r: SM[r] = `ITE(merge_cond`, S1[r], S2[r])
    ///   - All constraints from both states are disjunctively joined.
    ///
    /// Returns `None` if the states cannot be merged (different PCs).
    pub fn merge_states(s1: &SxState, s2: &SxState) -> Option<SxState> {
        if s1.pc != s2.pc {
            return None;
        }
        let mut merged = SxState::new(s1.pc);
        merged.depth = s1.depth.min(s2.depth);
        // Build a merge condition from the last constraint of s1.
        let merge_cond = s1
            .constraints
            .last()
            .cloned()
            .unwrap_or_else(SymExpr::bool_true);
        // Merge registers.
        let all_regs: HashSet<String> = s1.regs.keys().chain(s2.regs.keys()).cloned().collect();
        for reg in all_regs {
            let v1 = s1.get_reg(&reg);
            let v2 = s2.get_reg(&reg);
            if v1 == v2 {
                merged.set_reg(&reg, v1);
            } else {
                let ite = SymExpr::ITE(Box::new(merge_cond.clone()), Box::new(v1), Box::new(v2));
                merged.set_reg(&reg, ite.simplify());
            }
        }
        // Join constraints as disjunction.
        if !s1.constraints.is_empty() && !s2.constraints.is_empty() {
            let c1_conj = fold_and(&s1.constraints);
            let c2_conj = fold_and(&s2.constraints);
            merged.add_constraint(SymExpr::Or(Box::new(c1_conj), Box::new(c2_conj)).simplify());
        }
        Some(merged)
    }

    fn fold_and(cs: &[SymExpr]) -> SymExpr {
        cs.iter()
            .cloned()
            .reduce(|a, b| SymExpr::And(Box::new(a), Box::new(b)).simplify())
            .unwrap_or_else(SymExpr::bool_true)
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Concolic Execution Helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// A concolic input value: simultaneously concrete and symbolic.
    #[derive(Debug, Clone)]
    pub struct ConcolicValue {
        pub concrete: u64,
        pub symbolic: SymExpr,
        pub size: u8,
    }

    impl ConcolicValue {
        #[must_use]
        pub const fn from_concrete(v: u64, size: u8) -> Self {
            Self {
                concrete: v,
                symbolic: SymExpr::Const(v, size),
                size,
            }
        }

        #[must_use]
        pub const fn from_symbol(id: u32, concrete_guess: u64, size: u8) -> Self {
            Self {
                concrete: concrete_guess,
                symbolic: SymExpr::Symbol(id, size),
                size,
            }
        }

        /// Evaluate this value concretely.
        #[must_use]
        pub fn eval(&self) -> u64 {
            let mut m = HashMap::new();
            if let SymExpr::Symbol(id, _) = &self.symbolic {
                m.insert(*id, self.concrete);
            }
            self.symbolic.evaluate_concrete(&m).unwrap_or(self.concrete)
        }

        /// Return a negated constraint for the concrete path taken.
        #[must_use]
        pub fn negate_path_constraint(&self, taken: bool) -> SymExpr {
            if taken {
                SymExpr::Not(Box::new(self.symbolic.clone())).simplify()
            } else {
                self.symbolic.clone()
            }
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Coverage Tracking Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Tracks which basic blocks have been executed.
    #[derive(Debug, Clone, Default)]
    pub struct CoverageMap {
        /// Set of covered basic block entry addresses.
        pub covered: HashSet<u64>,
        /// Execution count per address.
        pub exec_count: HashMap<u64, u64>,
        /// Total target addresses (for percent calculation).
        pub total_targets: usize,
    }

    impl CoverageMap {
        #[must_use]
        pub fn new(total_targets: usize) -> Self {
            Self {
                covered: HashSet::new(),
                exec_count: HashMap::new(),
                total_targets,
            }
        }

        /// Mark address as covered.
        pub fn cover(&mut self, addr: u64) {
            self.covered.insert(addr);
            *self.exec_count.entry(addr).or_insert(0) += 1;
        }

        /// Coverage percentage (0.0Ã¢â‚¬â€œ100.0).
        #[must_use]
        pub fn percent(&self) -> f64 {
            if self.total_targets == 0 {
                return 0.0;
            }
            let covered = f64::from(u32::try_from(self.covered.len()).unwrap_or(u32::MAX));
            let total = f64::from(u32::try_from(self.total_targets).unwrap_or(u32::MAX));
            (covered / total) * 100.0
        }

        /// Addresses never covered.
        #[must_use]
        pub fn uncovered<'a>(&'a self, all: &'a [u64]) -> Vec<&'a u64> {
            all.iter().filter(|a| !self.covered.contains(a)).collect()
        }

        /// Number of covered addresses.
        #[must_use]
        pub fn covered_count(&self) -> usize {
            self.covered.len()
        }

        /// Total execution events recorded.
        #[must_use]
        pub fn total_executions(&self) -> u64 {
            self.exec_count.values().sum()
        }

        /// Hottest address (most executed).
        #[must_use]
        pub fn hottest(&self) -> Option<(u64, u64)> {
            self.exec_count
                .iter()
                .max_by_key(|(_, v)| *v)
                .map(|(&k, &v)| (k, v))
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Symbolic Heap Model Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// A simple symbolic heap model that tracks allocations and frees.
    #[derive(Debug, Clone, Default)]
    pub struct SymbolicHeap {
        /// Allocation id -> (`base_addr_expr`, `size_expr`).
        pub allocations: HashMap<u32, (SymExpr, SymExpr)>,
        /// Freed allocation ids.
        pub freed: HashSet<u32>,
        /// Counter for allocation ids.
        next_id: u32,
        /// Counter for symbolic addresses.
        next_sym: u32,
    }

    impl SymbolicHeap {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Allocate a symbolic chunk.  Returns (`alloc_id`, `base_address_expression`).
        pub fn malloc(&mut self, size: SymExpr) -> (u32, SymExpr) {
            let id = self.next_id;
            self.next_id += 1;
            let addr = SymExpr::Symbol(0x8000_0000 + self.next_sym, 8);
            self.next_sym += 1;
            self.allocations.insert(id, (addr.clone(), size));
            (id, addr)
        }

        /// Free an allocation.  Returns `false` if double-free detected.
        pub fn free(&mut self, id: u32) -> bool {
            if self.freed.contains(&id) {
                return false;
            }
            self.freed.insert(id);
            true
        }

        /// Check if an address expression may point into a freed allocation.
        #[must_use]
        pub fn is_freed_ptr(&self, addr: &SymExpr) -> bool {
            for freed_id in &self.freed {
                if let Some((base, _size)) = self.allocations.get(freed_id)
                    && SymbolicMemory::may_alias(addr, base) {
                        return true;
                    }
            }
            false
        }

        /// Check if an address may be within a valid (non-freed) allocation.
        #[must_use]
        pub fn is_valid_ptr(&self, addr: &SymExpr) -> bool {
            for (id, (base, _size)) in &self.allocations {
                if self.freed.contains(id) {
                    continue;
                }
                if SymbolicMemory::may_alias(addr, base) {
                    return true;
                }
            }
            false
        }

        /// Number of live (non-freed) allocations.
        #[must_use]
        pub fn live_count(&self) -> usize {
            self.allocations.len() - self.freed.len()
        }

        /// Number of freed allocations.
        #[must_use]
        pub fn freed_count(&self) -> usize {
            self.freed.len()
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Inter-Procedural Summary Table Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Stores pre-computed function summaries for inlining during symbolic execution.
    #[derive(Debug, Clone, Default)]
    pub struct SummaryTable {
        summaries: HashMap<u64, ProcSummary>,
    }

    /// A procedure summary: maps symbolic input registers to output expressions.
    #[derive(Debug, Clone)]
    pub struct ProcSummary {
        pub address: u64,
        pub name: Option<String>,
        /// Input register names.
        pub input_regs: Vec<String>,
        /// Output: reg name -> expression over input symbols.
        pub output_regs: HashMap<String, SymExpr>,
        /// Whether the function may diverge.
        pub may_not_return: bool,
        /// Whether the function has side effects on memory.
        pub has_memory_effects: bool,
    }

    impl ProcSummary {
        #[must_use]
        pub fn new(address: u64) -> Self {
            Self {
                address,
                name: None,
                input_regs: Vec::new(),
                output_regs: HashMap::new(),
                may_not_return: false,
                has_memory_effects: false,
            }
        }

        /// Apply this summary to a state (simulated call).
        pub fn apply_to(&self, state: &mut SxState) {
            for (reg, expr) in &self.output_regs {
                state.set_reg(reg, expr.clone());
            }
        }

        /// Set the return value expression.
        pub fn set_return(&mut self, expr: SymExpr) {
            self.output_regs.insert("rax".to_string(), expr);
        }
    }

    impl SummaryTable {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        pub fn insert(&mut self, s: ProcSummary) {
            self.summaries.insert(s.address, s);
        }

        #[must_use]
        pub fn get(&self, addr: u64) -> Option<&ProcSummary> {
            self.summaries.get(&addr)
        }

        pub fn apply(&self, addr: u64, state: &mut SxState) -> bool {
            self.summaries.get(&addr).inspect(|s| s.apply_to(state)).is_some()
        }

        #[must_use]
        pub fn count(&self) -> usize {
            self.summaries.len()
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Path Condition Printer Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Pretty-prints a set of path conditions for human-readable output.
    #[must_use]
    pub fn format_path_conditions(constraints: &[SymExpr]) -> String {
        use std::fmt::Write as _;
        if constraints.is_empty() {
            return "  (no constraints)".to_string();
        }
        let mut out = String::new();
        for (i, c) in constraints.iter().enumerate() {
            writeln!(out, "  [{i}] {}", c.to_smtlib2()).unwrap();
        }
        out
    }

    /// Compute the depth of a `SymExpr` AST.
    #[must_use]
    pub fn expr_depth(e: &SymExpr) -> usize {
        match e {
            SymExpr::Const(..) | SymExpr::Symbol(..) => 0,
            SymExpr::Not(x)
            | SymExpr::Neg(x)
            | SymExpr::ZExt(x, _)
            | SymExpr::SExt(x, _)
            | SymExpr::Trunc(x, _)
            | SymExpr::Extract(x, _, _)
            | SymExpr::Load(x, _) => 1 + expr_depth(x),
            SymExpr::Add(a, b)
            | SymExpr::Sub(a, b)
            | SymExpr::Mul(a, b)
            | SymExpr::UDiv(a, b)
            | SymExpr::SDiv(a, b)
            | SymExpr::And(a, b)
            | SymExpr::Or(a, b)
            | SymExpr::Xor(a, b)
            | SymExpr::Shl(a, b)
            | SymExpr::LShr(a, b)
            | SymExpr::AShr(a, b)
            | SymExpr::Concat(a, b)
            | SymExpr::Eq(a, b)
            | SymExpr::Ne(a, b)
            | SymExpr::Ult(a, b)
            | SymExpr::Ule(a, b)
            | SymExpr::Ugt(a, b)
            | SymExpr::Uge(a, b)
            | SymExpr::Slt(a, b)
            | SymExpr::Sle(a, b)
            | SymExpr::Sgt(a, b)
            | SymExpr::Sge(a, b) => 1 + expr_depth(a).max(expr_depth(b)),
            SymExpr::ITE(c, t, f) => 1 + expr_depth(c).max(expr_depth(t)).max(expr_depth(f)),
        }
    }

    /// Count the total number of nodes in a `SymExpr` AST.
    #[must_use]
    pub fn expr_node_count(e: &SymExpr) -> usize {
        match e {
            SymExpr::Const(..) | SymExpr::Symbol(..) => 1,
            SymExpr::Not(x)
            | SymExpr::Neg(x)
            | SymExpr::ZExt(x, _)
            | SymExpr::SExt(x, _)
            | SymExpr::Trunc(x, _)
            | SymExpr::Extract(x, _, _)
            | SymExpr::Load(x, _) => 1 + expr_node_count(x),
            SymExpr::Add(a, b)
            | SymExpr::Sub(a, b)
            | SymExpr::Mul(a, b)
            | SymExpr::UDiv(a, b)
            | SymExpr::SDiv(a, b)
            | SymExpr::And(a, b)
            | SymExpr::Or(a, b)
            | SymExpr::Xor(a, b)
            | SymExpr::Shl(a, b)
            | SymExpr::LShr(a, b)
            | SymExpr::AShr(a, b)
            | SymExpr::Concat(a, b)
            | SymExpr::Eq(a, b)
            | SymExpr::Ne(a, b)
            | SymExpr::Ult(a, b)
            | SymExpr::Ule(a, b)
            | SymExpr::Ugt(a, b)
            | SymExpr::Uge(a, b)
            | SymExpr::Slt(a, b)
            | SymExpr::Sle(a, b)
            | SymExpr::Sgt(a, b)
            | SymExpr::Sge(a, b) => 1 + expr_node_count(a) + expr_node_count(b),
            SymExpr::ITE(c, t, f) => {
                1 + expr_node_count(c) + expr_node_count(t) + expr_node_count(f)
            }
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Solver Query Cache Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Cache for solver query results to avoid re-querying identical constraint sets.
    #[derive(Debug, Clone, Default)]
    pub struct SolverCache {
        cache: HashMap<u64, bool>,
        hits: u64,
        misses: u64,
    }

    impl SolverCache {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        fn hash_constraints(cs: &[SymExpr]) -> u64 {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            for c in cs {
                format!("{c:?}").hash(&mut h);
            }
            h.finish()
        }

        /// Check the cache. Returns `Some(result)` on hit, `None` on miss.
        pub fn lookup(&mut self, constraints: &[SymExpr]) -> Option<bool> {
            let key = Self::hash_constraints(constraints);
            if let Some(&v) = self.cache.get(&key) {
                self.hits += 1;
                Some(v)
            } else {
                self.misses += 1;
                None
            }
        }

        /// Store a result in the cache.
        pub fn store(&mut self, constraints: &[SymExpr], result: bool) {
            let key = Self::hash_constraints(constraints);
            self.cache.insert(key, result);
        }

        #[must_use]
        pub const fn hit_count(&self) -> u64 {
            self.hits
        }
        #[must_use]
        pub const fn miss_count(&self) -> u64 {
            self.misses
        }
        #[must_use]
        pub fn cache_size(&self) -> usize {
            self.cache.len()
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Symbolic Slice Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Backward program slice: collect all operations that influence `target_reg`
    /// at `target_pc`.
    #[derive(Debug, Clone, Default)]
    pub struct BackwardSlice {
        /// Registers in the slice.
        pub regs: HashSet<String>,
        /// PCs of instructions in the slice.
        pub pcs: HashSet<u64>,
        /// Memory addresses in the slice.
        pub mem_addrs: HashSet<u64>,
    }

    impl BackwardSlice {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a register to the slice criterion.
        pub fn add_reg(&mut self, r: &str) {
            self.regs.insert(r.to_string());
        }

        /// Add a PC to the slice.
        pub fn add_pc(&mut self, pc: u64) {
            self.pcs.insert(pc);
        }

        /// Whether a given op is in the slice (uses any sliced register).
        #[must_use]
        pub fn contains_op(&self, op: &LlilOp) -> bool {
            match op {
                LlilOp::RegWrite { dst, .. } => self.regs.contains(dst),
                LlilOp::MemWrite { addr, .. } => {
                    if let LlilExpr::Const(a, _) = addr {
                        self.mem_addrs.contains(a)
                    } else {
                        true
                    }
                }
                _ => false,
            }
        }

        /// Size of the slice.
        #[must_use]
        pub fn size(&self) -> usize {
            self.regs.len() + self.pcs.len() + self.mem_addrs.len()
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Tests for extended analysis Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[cfg(test)]
    mod tests {
        use super::*;

        fn c8(v: u64) -> SymExpr {
            SymExpr::Const(v, 8)
        }
        fn c1(v: u64) -> SymExpr {
            SymExpr::Const(v, 1)
        }
        fn sym(id: u32) -> SymExpr {
            SymExpr::Symbol(id, 8)
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ simplify_constraints Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn simplify_drops_trivially_true() {
            let cs = vec![c1(1), SymExpr::Eq(Box::new(sym(0)), Box::new(c8(5)))];
            let simplified = simplify_constraints(&cs);
            assert!(!simplified.iter().any(|c| matches!(c, SymExpr::Const(1, _))));
        }
        #[test]
        fn simplify_keeps_real_constraints() {
            let cs = vec![SymExpr::Ult(Box::new(sym(0)), Box::new(c8(100)))];
            let s = simplify_constraints(&cs);
            assert_eq!(s.len(), 1);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ has_contradiction Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn contradiction_false_const() {
            assert!(has_contradiction(&[c1(0)]));
        }
        #[test]
        fn contradiction_two_eq_values() {
            let c1_e = SymExpr::Eq(Box::new(sym(0)), Box::new(c8(5)));
            let c2_e = SymExpr::Eq(Box::new(sym(0)), Box::new(c8(6)));
            assert!(has_contradiction(&[c1_e, c2_e]));
        }
        #[test]
        fn no_contradiction_consistent() {
            let c1_e = SymExpr::Eq(Box::new(sym(0)), Box::new(c8(5)));
            let c2_e = SymExpr::Eq(Box::new(sym(0)), Box::new(c8(5)));
            assert!(!has_contradiction(&[c1_e, c2_e]));
        }
        #[test]
        fn no_contradiction_no_constraints() {
            assert!(!has_contradiction(&[]));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ LoopBoundAnalysis Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn loop_bound_default() {
            let la = LoopBoundAnalysis::new(10);
            assert_eq!(la.get_bound(0x1000), 10);
        }
        #[test]
        fn loop_bound_set() {
            let mut la = LoopBoundAnalysis::new(10);
            la.set_bound(0x1000, 5);
            assert_eq!(la.get_bound(0x1000), 5);
        }
        #[test]
        fn loop_header_detection() {
            let mut la = LoopBoundAnalysis::new(10);
            la.add_back_edge(0x1100, 0x1000);
            assert!(la.is_loop_header(0x1000));
            assert!(!la.is_loop_header(0x2000));
        }
        #[test]
        fn loop_count() {
            let mut la = LoopBoundAnalysis::new(10);
            la.add_back_edge(0x1100, 0x1000);
            la.add_back_edge(0x2200, 0x2000);
            assert_eq!(la.loop_count(), 2);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ merge_states Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn merge_same_pc() {
            let mut s1 = SxState::new(0x1000);
            s1.set_reg("rax", c8(1));
            let mut s2 = SxState::new(0x1000);
            s2.set_reg("rax", c8(2));
            let m = merge_states(&s1, &s2);
            assert!(m.is_some());
            assert_eq!(m.unwrap().pc, 0x1000);
        }
        #[test]
        fn merge_diff_pc_returns_none() {
            let s1 = SxState::new(0x1000);
            let s2 = SxState::new(0x2000);
            assert!(merge_states(&s1, &s2).is_none());
        }
        #[test]
        fn merge_shared_reg_value_no_ite() {
            let mut s1 = SxState::new(0x1000);
            s1.set_reg("rax", c8(42));
            let mut s2 = SxState::new(0x1000);
            s2.set_reg("rax", c8(42));
            let m = merge_states(&s1, &s2).unwrap();
            assert_eq!(m.get_reg("rax"), c8(42));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ ConcolicValue Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn concolic_from_concrete() {
            let cv = ConcolicValue::from_concrete(42, 8);
            assert_eq!(cv.eval(), 42);
            assert!(cv.symbolic.is_concrete());
        }
        #[test]
        fn concolic_from_symbol_eval_guess() {
            let cv = ConcolicValue::from_symbol(0, 99, 8);
            assert_eq!(cv.eval(), 99);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ CoverageMap Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn coverage_basic() {
            let mut cm = CoverageMap::new(4);
            cm.cover(0x1000);
            cm.cover(0x2000);
            assert_eq!(cm.covered_count(), 2);
            assert!((cm.percent() - 50.0_f64).abs() < f64::EPSILON * 100.0);
        }
        #[test]
        fn coverage_uncovered() {
            let mut cm = CoverageMap::new(2);
            cm.cover(0x1000);
            let all = vec![0x1000u64, 0x2000u64];
            let unc = cm.uncovered(&all);
            assert_eq!(unc.len(), 1);
            assert_eq!(*unc[0], 0x2000u64);
        }
        #[test]
        fn coverage_total_executions() {
            let mut cm = CoverageMap::new(1);
            cm.cover(0x1000);
            cm.cover(0x1000);
            assert_eq!(cm.total_executions(), 2);
        }
        #[test]
        fn coverage_hottest() {
            let mut cm = CoverageMap::new(2);
            cm.cover(0x1000);
            cm.cover(0x1000);
            cm.cover(0x2000);
            let (addr, count) = cm.hottest().unwrap();
            assert_eq!(addr, 0x1000);
            assert_eq!(count, 2);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SymbolicHeap Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn heap_malloc_live() {
            let mut h = SymbolicHeap::new();
            let (_id, _addr) = h.malloc(SymExpr::Const(32, 8));
            assert_eq!(h.live_count(), 1);
        }
        #[test]
        fn heap_free_reduces_live() {
            let mut h = SymbolicHeap::new();
            let (id, _) = h.malloc(SymExpr::Const(64, 8));
            assert!(h.free(id));
            assert_eq!(h.live_count(), 0);
            assert_eq!(h.freed_count(), 1);
        }
        #[test]
        fn heap_double_free_detected() {
            let mut h = SymbolicHeap::new();
            let (id, _) = h.malloc(SymExpr::Const(16, 8));
            assert!(h.free(id));
            assert!(!h.free(id));
        }
        #[test]
        fn heap_freed_ptr_detected() {
            let mut h = SymbolicHeap::new();
            let (id, addr) = h.malloc(SymExpr::Const(8, 8));
            h.free(id);
            assert!(h.is_freed_ptr(&addr));
        }
        #[test]
        fn heap_valid_ptr() {
            let mut h = SymbolicHeap::new();
            let (_id, addr) = h.malloc(SymExpr::Const(8, 8));
            assert!(h.is_valid_ptr(&addr));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SummaryTable Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn summary_table_insert_get() {
            let mut t = SummaryTable::new();
            let mut s = ProcSummary::new(0xDEAD);
            s.name = Some("target_func".to_string());
            s.set_return(c8(42));
            t.insert(s);
            assert_eq!(t.count(), 1);
            assert!(t.get(0xDEAD).is_some());
            assert_eq!(
                t.get(0xDEAD).unwrap().output_regs.get("rax").unwrap(),
                &c8(42)
            );
        }
        #[test]
        fn summary_table_apply() {
            let mut t = SummaryTable::new();
            let mut s = ProcSummary::new(0x5000);
            s.set_return(c8(99));
            t.insert(s);
            let mut state = SxState::new(0);
            let applied = t.apply(0x5000, &mut state);
            assert!(applied);
            assert_eq!(state.get_reg("rax"), c8(99));
        }
        #[test]
        fn summary_table_miss() {
            let t = SummaryTable::new();
            let mut state = SxState::new(0);
            assert!(!t.apply(0xBAD, &mut state));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ SolverCache Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn solver_cache_miss_then_hit() {
            let mut c = SolverCache::new();
            let cs = vec![SymExpr::Eq(Box::new(sym(0)), Box::new(c8(5)))];
            assert!(c.lookup(&cs).is_none());
            c.store(&cs, true);
            assert_eq!(c.lookup(&cs), Some(true));
            assert_eq!(c.hit_count(), 1);
            assert_eq!(c.miss_count(), 1);
        }
        #[test]
        fn solver_cache_different_constraints() {
            let mut c = SolverCache::new();
            let cs1 = vec![c1(1)];
            let cs2 = vec![c1(0)];
            c.store(&cs1, true);
            c.store(&cs2, false);
            assert_eq!(c.lookup(&cs1), Some(true));
            assert_eq!(c.lookup(&cs2), Some(false));
            assert_eq!(c.cache_size(), 2);
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ expr_depth / expr_node_count Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn expr_depth_const() {
            assert_eq!(expr_depth(&c8(0)), 0);
        }
        #[test]
        fn expr_depth_add() {
            assert_eq!(
                expr_depth(&SymExpr::Add(Box::new(c8(1)), Box::new(c8(2)))),
                1
            );
        }
        #[test]
        fn expr_depth_nested() {
            let e = SymExpr::Add(
                Box::new(SymExpr::Add(Box::new(c8(1)), Box::new(c8(2)))),
                Box::new(c8(3)),
            );
            assert_eq!(expr_depth(&e), 2);
        }
        #[test]
        fn expr_nodes_const() {
            assert_eq!(expr_node_count(&c8(0)), 1);
        }
        #[test]
        fn expr_nodes_add() {
            assert_eq!(
                expr_node_count(&SymExpr::Add(Box::new(c8(1)), Box::new(c8(2)))),
                3
            );
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ BackwardSlice Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn slice_add_reg() {
            let mut s = BackwardSlice::new();
            s.add_reg("rax");
            assert_eq!(s.size(), 1);
            assert!(s.regs.contains("rax"));
        }
        #[test]
        fn slice_contains_op_match() {
            let mut s = BackwardSlice::new();
            s.add_reg("rbx");
            let op = LlilOp::RegWrite {
                dst: "rbx".to_string(),
                src: LlilExpr::Const(1, 8),
            };
            assert!(s.contains_op(&op));
        }
        #[test]
        fn slice_contains_op_no_match() {
            let mut s = BackwardSlice::new();
            s.add_reg("rax");
            let op = LlilOp::RegWrite {
                dst: "rcx".to_string(),
                src: LlilExpr::Const(1, 8),
            };
            assert!(!s.contains_op(&op));
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ format_path_conditions Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        #[test]
        fn format_empty_constraints() {
            let s = format_path_conditions(&[]);
            assert!(s.contains("no constraints"));
        }
        #[test]
        fn format_one_constraint() {
            let cs = vec![c1(1)];
            let s = format_path_conditions(&cs);
            assert!(s.contains("[0]"));
        }
    }
} // mod analysis

/// Vulnerability-specific analysis and reporting utilities.
pub mod vuln_analysis {

    use super::full_symex::{LlilOp, SxState, eval_expr, SymExpr, LlilExpr};
    use std::collections::{HashMap, HashSet};

    // Ã¢â€â‚¬Ã¢â€â‚¬ Vulnerability Scanner Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Categories of vulnerabilities the scanner can detect.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum VulnCategory {
        MemorySafety,
        IntegerSafety,
        FormatString,
        CommandInjection,
        TypeConfusion,
        RaceCondition,
        OutOfBounds,
        UninitialisedRead,
    }

    /// Severity level for vulnerability reports.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Severity {
        Info,
        Low,
        Medium,
        High,
        Critical,
    }

    /// A rich vulnerability report with context.
    #[derive(Debug, Clone)]
    pub struct VulnReport {
        pub category: VulnCategory,
        pub severity: Severity,
        pub pc: u64,
        pub description: String,
        pub smt_witness: Option<String>,
        pub cwe: Option<u32>,
    }

    impl VulnReport {
        pub fn new(cat: VulnCategory, sev: Severity, pc: u64, desc: impl Into<String>) -> Self {
            Self {
                category: cat,
                severity: sev,
                pc,
                description: desc.into(),
                smt_witness: None,
                cwe: None,
            }
        }

        #[must_use]
        pub const fn with_cwe(mut self, cwe: u32) -> Self {
            self.cwe = Some(cwe);
            self
        }
        #[must_use]
        pub fn with_witness(mut self, w: String) -> Self {
            self.smt_witness = Some(w);
            self
        }
    }

    /// Scans a symbolic state and list of ops for vulnerabilities.
    #[derive(Debug, Default)]
    pub struct VulnScanner {
        pub reports: Vec<VulnReport>,
    }

    impl VulnScanner {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Scan a single operation in the context of a symbolic state.
        pub fn scan_op(&mut self, op: &LlilOp, state: &SxState) {
            match op {
                LlilOp::MemRead { addr, .. } | LlilOp::MemWrite { addr, .. } => {
                    let addr_sym = eval_expr(addr, state);
                    // Null dereference check.
                    if matches!(addr_sym, SymExpr::Const(0, _)) {
                        self.reports.push(
                            VulnReport::new(
                                VulnCategory::MemorySafety,
                                Severity::Critical,
                                state.pc,
                                "null pointer dereference (concrete 0)",
                            )
                            .with_cwe(476),
                        );
                    } else if !addr_sym.is_concrete() {
                        self.reports.push(
                            VulnReport::new(
                                VulnCategory::MemorySafety,
                                Severity::Medium,
                                state.pc,
                                "symbolic pointer dereference Ã¢â‚¬â€ may alias null",
                            )
                            .with_cwe(476),
                        );
                    }
                }
                LlilOp::UDiv { .. } | LlilOp::SDiv { .. } => {
                    self.reports.push(
                        VulnReport::new(
                            VulnCategory::IntegerSafety,
                            Severity::High,
                            state.pc,
                            "potential division by zero",
                        )
                        .with_cwe(369),
                    );
                }
                _ => {}
            }
            // Check for integer overflow in Add/Mul expressions within RegWrite.
            if let LlilOp::RegWrite { src, .. } = op {
                self.check_expr_overflow(src, state);
            }
        }

        fn check_expr_overflow(&mut self, expr: &LlilExpr, state: &SxState) {
            match expr {
                LlilExpr::Add(a, b) | LlilExpr::Mul(a, b) => {
                    let as_ = eval_expr(a, state);
                    let bs_ = eval_expr(b, state);
                    if !as_.is_concrete() || !bs_.is_concrete() {
                        self.reports.push(
                            VulnReport::new(
                                VulnCategory::IntegerSafety,
                                Severity::Low,
                                state.pc,
                                "symbolic arithmetic may overflow",
                            )
                            .with_cwe(190),
                        );
                    }
                }
                _ => {}
            }
        }

        /// Scan an entire basic block.
        pub fn scan_block(&mut self, ops: &[LlilOp], state: &SxState) {
            for op in ops {
                self.scan_op(op, state);
            }
        }

        /// Severity distribution of all reports.
        #[must_use]
        pub fn severity_counts(&self) -> HashMap<String, usize> {
            let mut m: HashMap<String, usize> = HashMap::new();
            for r in &self.reports {
                let k = format!("{:?}", r.severity);
                *m.entry(k).or_insert(0) += 1;
            }
            m
        }

        /// Filter reports by minimum severity.
        #[must_use]
        pub fn filter_by_severity(&self, min: &Severity) -> Vec<&VulnReport> {
            self.reports.iter().filter(|r| r.severity >= *min).collect()
        }

        #[must_use]
        pub const fn report_count(&self) -> usize {
            self.reports.len()
        }
        pub fn clear(&mut self) {
            self.reports.clear();
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Symbolic Execution Trace Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// A trace of symbolic execution: sequence of (pc, `op_description`, `state_id`).
    #[derive(Debug, Clone, Default)]
    pub struct ExecTrace {
        pub entries: Vec<TraceEntry>,
    }

    #[derive(Debug, Clone)]
    pub struct TraceEntry {
        pub pc: u64,
        pub state_id: u64,
        pub depth: u32,
        pub op_desc: String,
        pub constraint_count: usize,
    }

    impl ExecTrace {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        pub fn record(&mut self, state: &SxState, op: &LlilOp) {
            self.entries.push(TraceEntry {
                pc: state.pc,
                state_id: state.id,
                depth: state.depth,
                op_desc: format!("{op:?}"),
                constraint_count: state.constraint_count(),
            });
        }

        #[must_use]
        pub const fn len(&self) -> usize {
            self.entries.len()
        }
        #[must_use]
        pub const fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }

        /// Unique PCs in the trace (ordered by first occurrence).
        #[must_use]
        pub fn unique_pcs(&self) -> Vec<u64> {
            let mut seen = HashSet::new();
            self.entries
                .iter()
                .filter_map(|e| if seen.insert(e.pc) { Some(e.pc) } else { None })
                .collect()
        }

        /// Maximum depth reached in this trace.
        #[must_use]
        pub fn max_depth(&self) -> u32 {
            self.entries.iter().map(|e| e.depth).max().unwrap_or(0)
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Tests Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[cfg(test)]
    mod tests {
        use super::*;

        fn _c8(v: u64) -> SymExpr {
            SymExpr::Const(v, 8)
        }
        fn _sym(id: u32) -> SymExpr {
            SymExpr::Symbol(id, 8)
        }

        #[test]
        fn vuln_scanner_null_deref_concrete() {
            let mut scanner = VulnScanner::new();
            let state = SxState::new(0x1000);
            let op = LlilOp::MemRead {
                dst: "rax".to_string(),
                addr: LlilExpr::Const(0, 8),
                size: 8,
            };
            scanner.scan_op(&op, &state);
            assert_eq!(scanner.report_count(), 1);
            assert!(matches!(
                scanner.reports[0].category,
                VulnCategory::MemorySafety
            ));
            assert_eq!(scanner.reports[0].cwe, Some(476));
        }

        #[test]
        fn vuln_scanner_symbolic_ptr() {
            let mut scanner = VulnScanner::new();
            let state = SxState::new(0x2000);
            let op = LlilOp::MemRead {
                dst: "rax".to_string(),
                addr: LlilExpr::Reg("rbx".to_string()),
                size: 8,
            };
            scanner.scan_op(&op, &state);
            assert!(!scanner.reports.is_empty());
        }

        #[test]
        fn vuln_scanner_clear() {
            let mut scanner = VulnScanner::new();
            let state = SxState::new(0);
            let op = LlilOp::MemRead {
                dst: "x".to_string(),
                addr: LlilExpr::Const(0, 8),
                size: 8,
            };
            scanner.scan_op(&op, &state);
            assert!(scanner.report_count() > 0);
            scanner.clear();
            assert_eq!(scanner.report_count(), 0);
        }

        #[test]
        fn vuln_scanner_filter_severity() {
            let mut scanner = VulnScanner::new();
            scanner.reports.push(VulnReport::new(
                VulnCategory::MemorySafety,
                Severity::Low,
                0,
                "low",
            ));
            scanner.reports.push(VulnReport::new(
                VulnCategory::IntegerSafety,
                Severity::Critical,
                0,
                "critical",
            ));
            let high_plus = scanner.filter_by_severity(&Severity::High);
            assert_eq!(high_plus.len(), 1);
            assert_eq!(high_plus[0].severity, Severity::Critical);
        }

        #[test]
        fn severity_ordering() {
            assert!(Severity::Critical > Severity::High);
            assert!(Severity::High > Severity::Medium);
            assert!(Severity::Medium > Severity::Low);
            assert!(Severity::Low > Severity::Info);
        }

        #[test]
        fn exec_trace_record_and_query() {
            let mut trace = ExecTrace::new();
            let state = SxState::new(0x1000);
            let op = LlilOp::Nop;
            trace.record(&state, &op);
            assert_eq!(trace.len(), 1);
            assert_eq!(trace.unique_pcs(), vec![0x1000]);
            assert_eq!(trace.max_depth(), 0);
        }

        #[test]
        fn exec_trace_unique_pcs_dedup() {
            let mut trace = ExecTrace::new();
            let s = SxState::new(0x1000);
            trace.record(&s, &LlilOp::Nop);
            trace.record(&s, &LlilOp::Nop);
            assert_eq!(trace.unique_pcs().len(), 1);
        }

        #[test]
        fn exec_trace_max_depth() {
            let mut trace = ExecTrace::new();
            let s = SxState::new(0x1000);
            trace.record(&s, &LlilOp::Nop);
            let (child, _) = s.fork();
            let (grandchild, _) = child.fork();
            trace.record(&grandchild, &LlilOp::Nop);
            assert_eq!(trace.max_depth(), 2);
        }

        #[test]
        fn vuln_report_with_cwe() {
            let r = VulnReport::new(VulnCategory::OutOfBounds, Severity::High, 0x500, "oob")
                .with_cwe(125);
            assert_eq!(r.cwe, Some(125));
        }

        #[test]
        fn vuln_report_with_witness() {
            let r = VulnReport::new(VulnCategory::FormatString, Severity::High, 0, "fmt")
                .with_witness("(sat)".to_string());
            assert_eq!(r.smt_witness.as_deref(), Some("(sat)"));
        }

        #[test]
        fn vuln_scanner_severity_counts() {
            let mut s = VulnScanner::new();
            s.reports.push(VulnReport::new(
                VulnCategory::MemorySafety,
                Severity::High,
                0,
                "a",
            ));
            s.reports.push(VulnReport::new(
                VulnCategory::MemorySafety,
                Severity::High,
                0,
                "b",
            ));
            s.reports.push(VulnReport::new(
                VulnCategory::IntegerSafety,
                Severity::Low,
                0,
                "c",
            ));
            let counts = s.severity_counts();
            assert_eq!(counts.get("High").copied().unwrap_or(0), 2);
            assert_eq!(counts.get("Low").copied().unwrap_or(0), 1);
        }
    }
} // mod vuln_analysis
