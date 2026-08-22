//! `rustre-analysis-dataflow`
//!
//! Data flow analysis framework for the `RustRE` Suite.
//!
//! Provides a generic worklist-based framework for forward and backward data flow
//! analyses operating over control flow graphs (CFGs). Includes classic analyses:
//! live variable analysis, reaching definitions, available expressions, and very
//! busy expressions, plus def-use / use-def chain building and an interprocedural
//! skeleton.

pub mod alias_analysis;
pub mod cfg_dom;
pub mod constant_propagation;
pub mod def_use;
pub mod def_use_analysis;
pub mod du_chains;
pub mod live_ranges;
pub mod reaching_definitions;
pub mod reaching_defs;
pub mod ssa;
pub mod value_range;

/// Andersen-style pointer analysis.
///
/// `ConstraintGraph`, `AddressOf`/`Assign`/`Load`/`Store`
/// constraints, `WorklistSolver`, `PointsToSets`, `AndersenPointerAnalysis`.
pub mod pointer_analysis;

pub mod ssa_optimizer;
pub mod available_expressions;
pub mod constant_propagator;

#[cfg(test)]
mod prop_soundness;

/// Shared test-only constructors (one definition instead of the nine
/// byte-identical `fn sv` copies the test modules used to carry).
#[cfg(test)]
pub(crate) mod test_util {
    use crate::ssa::{SsaVar, Var};

    /// `SsaVar` from a name and version — the ubiquitous test shorthand.
    pub(crate) fn sv(name: &str, ver: u32) -> SsaVar {
        SsaVar::new(Var::new(name), ver)
    }
}

/// Differential tests: `lib.rs` dominance vs `cfg_dom` dominance.
#[cfg(test)]
mod dom_differential;

#[cfg(test)]
mod prop_soundness_ext;
/// Randomized lattice/oracle property tests (compiled only under `cfg(test)`).
mod prop_lattice_oracle;

pub use du_chains::{DefUseChains, LinearScan, LiveInterval, ProgramPoint, base_interference};

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ────────────────────────────────────────────────────────────────────────────
// Error type
// ────────────────────────────────────────────────────────────────────────────

/// Errors produced by the data flow analysis framework.
#[derive(Debug, Error)]
pub enum DataFlowError {
    #[error("CFG node {0} not found")]
    NodeNotFound(usize),
    #[error("analysis did not converge after {0} iterations")]
    NoConvergence(usize),
    #[error("empty CFG — no entry node")]
    EmptyCfg,
    /// A `bb_id` appeared more than once in a `cfg_nodes`/`cfg` slice passed to
    /// one of the `*_checked` entry points (e.g. [`compute_liveness_checked`],
    /// [`compute_reaching_defs_checked`], [`insert_phi_nodes_checked`]).
    /// The unchecked siblings silently collapse duplicates to last-write-wins
    /// instead of returning this error.
    #[error("duplicate basic-block id {0} in input")]
    DuplicateBbId(u32),
}

/// Scan a slice of `bb_id`s and return the first duplicate found, if any.
///
/// Uses an `FxHashSet` (attacker/user-controlled `bb_id`s should not hash to a
/// DoS-able collision-prone map) and stops at the first repeat, which keeps
/// this `O(n)` rather than needing a full duplicate report.
fn first_duplicate_bb_id(ids: impl Iterator<Item = u32>) -> Option<u32> {
    let mut seen: rustc_hash::FxHashSet<u32> = rustc_hash::FxHashSet::default();
    for id in ids {
        if !seen.insert(id) {
            return Some(id);
        }
    }
    None
}

// ────────────────────────────────────────────────────────────────────────────
// Lattice trait
// ────────────────────────────────────────────────────────────────────────────

/// A meet-semilattice used as the abstract domain for data flow facts.
///
/// `join` computes the least upper bound (∪ for sets, ∩ for must-analyses).
/// `meet` computes the greatest lower bound.
/// `bottom` is the identity element for `join`.
/// `top` is the identity element for `meet`.
pub trait Lattice: Clone + PartialEq + Debug {
    /// Least upper bound (join / ∨).
    #[must_use]
    fn join(&self, other: &Self) -> Self;
    /// Greatest lower bound (meet / ∧).
    #[must_use]
    fn meet(&self, other: &Self) -> Self;
    /// Bottom element (∅ for set-based lattices).
    fn bottom() -> Self;
    /// Top element (U for set-based lattices, where U is the universe).
    fn top() -> Self;
    /// Returns `true` when `self ⊑ other` (self is less-or-equal in the lattice).
    fn leq(&self, other: &Self) -> bool {
        self.join(other) == *other
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Bit-set lattice for Boolean / power-set domains
// ────────────────────────────────────────────────────────────────────────────

/// A compact bit-set lattice backed by a `HashSet<T>`.
/// `join` = union, `meet` = intersection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitSetLattice<T: Eq + Hash + Clone + Debug> {
    pub set: HashSet<T>,
    pub is_top: bool,
}

impl<T: Eq + Hash + Clone + Debug> Default for BitSetLattice<T> {
    fn default() -> Self {
        Self::bottom()
    }
}

impl<T: Eq + Hash + Clone + Debug> BitSetLattice<T> {
    #[must_use]
    pub const fn new(set: HashSet<T>) -> Self {
        Self { set, is_top: false }
    }

    pub fn contains(&self, item: &T) -> bool {
        self.is_top || self.set.contains(item)
    }
}

impl<T: Eq + Hash + Clone + Debug> Lattice for BitSetLattice<T> {
    fn join(&self, other: &Self) -> Self {
        if self.is_top || other.is_top {
            return Self {
                set: HashSet::new(),
                is_top: true,
            };
        }
        Self {
            set: self.set.union(&other.set).cloned().collect(),
            is_top: false,
        }
    }

    fn meet(&self, other: &Self) -> Self {
        if self.is_top {
            return other.clone();
        }
        if other.is_top {
            return self.clone();
        }
        Self {
            set: self.set.intersection(&other.set).cloned().collect(),
            is_top: false,
        }
    }

    fn bottom() -> Self {
        Self {
            set: HashSet::new(),
            is_top: false,
        }
    }

    fn top() -> Self {
        Self {
            set: HashSet::new(),
            is_top: true,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// CFG representation used by the framework
// ────────────────────────────────────────────────────────────────────────────

/// A node in the control flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgNode<S> {
    /// Unique node id.
    pub id: usize,
    /// Abstract statements / instructions in this basic block.
    pub stmts: Vec<S>,
}

/// A lightweight control flow graph used by the data flow framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cfg<S> {
    pub nodes: Vec<CfgNode<S>>,
    /// Successor edges: `successors[i]` contains node ids that follow node `i`.
    pub successors: Vec<Vec<usize>>,
    /// Predecessor edges (derived from successors).
    pub predecessors: Vec<Vec<usize>>,
    /// Index of the entry node (for forward analyses).
    pub entry: usize,
    /// Index of the exit node (for backward analyses).
    pub exit: usize,
}

impl<S: Clone> Cfg<S> {
    /// Build a CFG from nodes and successor lists.
    /// Predecessor edges are computed automatically.
    #[must_use]
    pub fn new(
        nodes: Vec<CfgNode<S>>,
        successors: Vec<Vec<usize>>,
        entry: usize,
        exit: usize,
    ) -> Self {
        let n = nodes.len();
        let mut predecessors = vec![Vec::new(); n];
        for (src, succs) in successors.iter().enumerate() {
            for &dst in succs {
                if dst < n {
                    predecessors[dst].push(src);
                }
            }
        }
        Self {
            nodes,
            successors,
            predecessors,
            entry,
            exit,
        }
    }

    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Direction marker
// ────────────────────────────────────────────────────────────────────────────

/// Whether an analysis traverses the CFG forward or backward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Backward,
}

// ────────────────────────────────────────────────────────────────────────────
// DataFlowAnalysis trait
// ────────────────────────────────────────────────────────────────────────────

/// Core trait for a data flow analysis.
///
/// Implementors define:
/// - The abstract fact type `Fact` (must implement `Lattice`).
/// - The direction (forward / backward).
/// - The boundary condition (value at entry for forward, exit for backward).
/// - The transfer function for a single CFG node.
pub trait DataFlowAnalysis {
    type Stmt: Clone + Debug;
    type Fact: Lattice;

    fn direction(&self) -> Direction;

    /// Boundary value injected at the entry (forward) or exit (backward) node.
    fn boundary(&self) -> Self::Fact;

    /// Initial value for all interior nodes before iteration begins.
    fn initial(&self) -> Self::Fact {
        Self::Fact::bottom()
    }

    /// Transfer function: given the data flow `fact` entering a node and the
    /// node's statements, return the fact leaving the node.
    fn transfer(&self, node: &CfgNode<Self::Stmt>, in_fact: &Self::Fact) -> Self::Fact;
}

// ────────────────────────────────────────────────────────────────────────────
// Worklist algorithm
// ────────────────────────────────────────────────────────────────────────────

/// Result of running the worklist algorithm.
#[derive(Debug, Clone)]
pub struct DataFlowResult<F> {
    /// Fact at the *entry* of each node (indexed by node id).
    pub in_facts: Vec<F>,
    /// Fact at the *exit* of each node (indexed by node id).
    pub out_facts: Vec<F>,
    /// Number of iterations until convergence.
    pub iterations: usize,
}

/// Maximum iterations before giving up (avoids infinite loops on buggy inputs).
const MAX_ITERATIONS: usize = 10_000;

/// Worklist-based data flow solver.
pub struct WorklistAlgorithm;

impl WorklistAlgorithm {
    /// Run `analysis` over `cfg`, iterate until a fixed point is reached.
    ///
    /// Returns `DataFlowResult` containing per-node in/out facts.
    ///
    /// # Errors
    ///
    /// Returns `DataFlowError::EmptyCfg` for an empty graph,
    /// `DataFlowError::NodeNotFound` if the graph is inconsistent, or
    /// `DataFlowError::NoConvergence` if the analysis does not converge.
    pub fn run<A>(
        analysis: &A,
        cfg: &Cfg<A::Stmt>,
    ) -> Result<DataFlowResult<A::Fact>, DataFlowError>
    where
        A: DataFlowAnalysis,
    {
        let n = cfg.node_count();
        if n == 0 {
            return Err(DataFlowError::EmptyCfg);
        }
        // `entry`/`exit` are plain `usize` fields on `Cfg` and are not
        // validated by `Cfg::new` — a malformed CFG (e.g. built by hand, or
        // from untrusted/deserialized input) with an out-of-range `entry` or
        // `exit` used to index straight into `in_facts`/`out_facts` below and
        // panic. Surface it as `NodeNotFound` instead, consistent with the
        // node-lookup error handling later in this loop.
        if cfg.entry >= n {
            return Err(DataFlowError::NodeNotFound(cfg.entry));
        }
        if cfg.exit >= n {
            return Err(DataFlowError::NodeNotFound(cfg.exit));
        }

        let mut in_facts: Vec<A::Fact> = (0..n).map(|_| analysis.initial()).collect();
        let mut out_facts: Vec<A::Fact> = (0..n).map(|_| analysis.initial()).collect();

        let forward = analysis.direction() == Direction::Forward;

        if forward {
            in_facts[cfg.entry] = analysis.boundary();
        } else {
            out_facts[cfg.exit] = analysis.boundary();
        }

        let mut worklist: VecDeque<usize> = (0..n).collect();
        let mut in_worklist: Vec<bool> = vec![true; n];

        let mut iterations = 0usize;

        while let Some(node_id) = worklist.pop_front() {
            in_worklist[node_id] = false;
            iterations += 1;
            if iterations > MAX_ITERATIONS {
                return Err(DataFlowError::NoConvergence(iterations));
            }

            let node = cfg
                .nodes
                .get(node_id)
                .ok_or(DataFlowError::NodeNotFound(node_id))?;

            // `predecessors`/`successors` are public `Vec<Vec<usize>>` fields
            // on `Cfg` — a caller building a `Cfg` by hand (rather than via
            // `Cfg::new`, which derives+filters predecessors) can supply
            // rows shorter than `n` or neighbor ids that are themselves
            // out-of-range. Look rows up with `.get()` and filter neighbor
            // ids by `< n` before using them to index `in_facts`/`out_facts`,
            // instead of panicking on malformed/adversarial input.
            let empty: Vec<usize> = Vec::new();

            if forward {
                let preds = cfg.predecessors.get(node_id).unwrap_or(&empty);
                let new_in = if node_id == cfg.entry {
                    analysis.boundary()
                } else {
                    let mut valid_preds = preds.iter().copied().filter(|&p| p < n);
                    if let Some(first) = valid_preds.next() {
                        let mut acc = out_facts[first].clone();
                        for pred in valid_preds {
                            acc = acc.join(&out_facts[pred]);
                        }
                        acc
                    } else {
                        analysis.initial()
                    }
                };

                let new_out = analysis.transfer(node, &new_in);

                if new_out != out_facts[node_id] {
                    out_facts[node_id] = new_out;
                    for &succ in cfg.successors.get(node_id).unwrap_or(&empty) {
                        if succ < n && !in_worklist[succ] {
                            in_worklist[succ] = true;
                            worklist.push_back(succ);
                        }
                    }
                }
                in_facts[node_id] = new_in;
            } else {
                let succs = cfg.successors.get(node_id).unwrap_or(&empty);
                let new_out = if node_id == cfg.exit {
                    analysis.boundary()
                } else {
                    let mut valid_succs = succs.iter().copied().filter(|&s| s < n);
                    if let Some(first) = valid_succs.next() {
                        let mut acc = in_facts[first].clone();
                        for succ in valid_succs {
                            acc = acc.join(&in_facts[succ]);
                        }
                        acc
                    } else {
                        analysis.initial()
                    }
                };

                let new_in = analysis.transfer(node, &new_out);

                if new_in != in_facts[node_id] {
                    in_facts[node_id] = new_in;
                    for &pred in cfg.predecessors.get(node_id).unwrap_or(&empty) {
                        if pred < n && !in_worklist[pred] {
                            in_worklist[pred] = true;
                            worklist.push_back(pred);
                        }
                    }
                }
                out_facts[node_id] = new_out;
            }
        }

        Ok(DataFlowResult {
            in_facts,
            out_facts,
            iterations,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Concrete statement model used by the classic analyses below
// ────────────────────────────────────────────────────────────────────────────

/// A simplified statement for demonstrating the classic analyses.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Statement {
    pub id: usize,
    pub def: Option<String>,
    pub uses: Vec<String>,
    pub expr: Option<String>,
}

impl Statement {
    pub fn new(id: usize, def: Option<&str>, uses: Vec<&str>) -> Self {
        Self {
            id,
            def: def.map(str::to_string),
            uses: uses.into_iter().map(str::to_string).collect(),
            expr: None,
        }
    }

    #[must_use]
    pub fn with_expr(mut self, expr: &str) -> Self {
        self.expr = Some(expr.to_string());
        self
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Live Variable Analysis (backward, may analysis)
// ────────────────────────────────────────────────────────────────────────────

/// Live variable analysis.
///
/// A variable `v` is *live* at a program point `p` if there is a path from
/// `p` to a use of `v` that does not pass through a definition of `v`.
///
/// Direction: backward.  Lattice: powerset of variables (join = union).
pub struct LiveVariableAnalysis;

impl DataFlowAnalysis for LiveVariableAnalysis {
    type Stmt = Statement;
    type Fact = BitSetLattice<String>;

    fn direction(&self) -> Direction {
        Direction::Backward
    }

    fn boundary(&self) -> Self::Fact {
        BitSetLattice::bottom()
    }

    fn transfer(&self, node: &CfgNode<Statement>, out_fact: &Self::Fact) -> Self::Fact {
        let mut result = out_fact.set.clone();
        for stmt in node.stmts.iter().rev() {
            if let Some(ref def_var) = stmt.def {
                result.remove(def_var);
            }
            for use_var in &stmt.uses {
                result.insert(use_var.clone());
            }
        }
        BitSetLattice::new(result)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Reaching Definitions Analysis (forward, may analysis)
// ────────────────────────────────────────────────────────────────────────────

/// A definition is identified by (variable name, statement id).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Definition {
    pub variable: String,
    pub stmt_id: usize,
}

/// Reaching definitions analysis.
///
/// A definition `d` of variable `v` *reaches* program point `p` if there
/// exists a CFG path from `d` to `p` along which `v` is not re-defined.
///
/// Direction: forward.  Lattice: powerset of definitions (join = union).
pub struct ReachingDefinitions;

impl DataFlowAnalysis for ReachingDefinitions {
    type Stmt = Statement;
    type Fact = BitSetLattice<Definition>;

    fn direction(&self) -> Direction {
        Direction::Forward
    }

    fn boundary(&self) -> Self::Fact {
        BitSetLattice::bottom()
    }

    fn transfer(&self, node: &CfgNode<Statement>, in_fact: &Self::Fact) -> Self::Fact {
        let mut result = in_fact.set.clone();
        for stmt in &node.stmts {
            if let Some(ref def_var) = stmt.def {
                result.retain(|d: &Definition| d.variable != *def_var);
                result.insert(Definition {
                    variable: def_var.clone(),
                    stmt_id: stmt.id,
                });
            }
        }
        BitSetLattice::new(result)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Available Expressions Analysis (forward, must analysis)
// ────────────────────────────────────────────────────────────────────────────

/// Available expressions analysis.
///
/// Direction: forward.  Lattice: powerset of expressions (join = intersection).
pub struct AvailableExpressions {
    pub universe: HashSet<String>,
}

impl AvailableExpressions {
    #[must_use]
    pub const fn new(universe: HashSet<String>) -> Self {
        Self { universe }
    }
}

/// Wraps a `HashSet<String>` with must-analysis join semantics (intersection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MustSet {
    pub set: HashSet<String>,
    pub is_top: bool,
}

impl MustSet {
    #[must_use]
    pub const fn new(set: HashSet<String>) -> Self {
        Self { set, is_top: false }
    }

    #[must_use]
    pub const fn top_with(universe: HashSet<String>) -> Self {
        Self {
            set: universe,
            is_top: true,
        }
    }
}

impl Lattice for MustSet {
    fn join(&self, other: &Self) -> Self {
        if self.is_top {
            return other.clone();
        }
        if other.is_top {
            return self.clone();
        }
        Self {
            set: self.set.intersection(&other.set).cloned().collect(),
            is_top: false,
        }
    }

    fn meet(&self, other: &Self) -> Self {
        if self.is_top || other.is_top {
            return Self {
                set: HashSet::new(),
                is_top: true,
            };
        }
        Self {
            set: self.set.union(&other.set).cloned().collect(),
            is_top: false,
        }
    }

    fn bottom() -> Self {
        Self {
            set: HashSet::new(),
            is_top: false,
        }
    }

    fn top() -> Self {
        Self {
            set: HashSet::new(),
            is_top: true,
        }
    }
}

impl DataFlowAnalysis for AvailableExpressions {
    type Stmt = Statement;
    type Fact = MustSet;

    fn direction(&self) -> Direction {
        Direction::Forward
    }

    fn boundary(&self) -> Self::Fact {
        MustSet::bottom()
    }

    fn initial(&self) -> Self::Fact {
        MustSet::top_with(self.universe.clone())
    }

    fn transfer(&self, node: &CfgNode<Statement>, in_fact: &Self::Fact) -> Self::Fact {
        let mut result = in_fact.set.clone();
        for stmt in &node.stmts {
            if let Some(ref def_var) = stmt.def {
                result.retain(|expr: &String| !expr.contains(def_var.as_str()));
                if let Some(ref expr) = stmt.expr {
                    result.insert(expr.clone());
                }
            }
        }
        MustSet::new(result)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Very Busy Expressions Analysis (backward, must analysis)
// ────────────────────────────────────────────────────────────────────────────

/// Very busy expressions analysis.
///
/// Direction: backward.  Lattice: powerset of expressions (join = intersection).
pub struct VeryBusyExpressions {
    pub universe: HashSet<String>,
}

impl VeryBusyExpressions {
    #[must_use]
    pub const fn new(universe: HashSet<String>) -> Self {
        Self { universe }
    }
}

impl DataFlowAnalysis for VeryBusyExpressions {
    type Stmt = Statement;
    type Fact = MustSet;

    fn direction(&self) -> Direction {
        Direction::Backward
    }

    fn boundary(&self) -> Self::Fact {
        MustSet::bottom()
    }

    fn initial(&self) -> Self::Fact {
        MustSet::top_with(self.universe.clone())
    }

    fn transfer(&self, node: &CfgNode<Statement>, out_fact: &Self::Fact) -> Self::Fact {
        let mut result = out_fact.set.clone();
        for stmt in node.stmts.iter().rev() {
            if let Some(ref def_var) = stmt.def {
                result.retain(|expr: &String| !expr.contains(def_var.as_str()));
            }
            if let Some(ref expr) = stmt.expr {
                result.insert(expr.clone());
            }
        }
        MustSet::new(result)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Def-Use and Use-Def chains
// ────────────────────────────────────────────────────────────────────────────

/// A use of a variable: the statement id where the variable is read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UsePoint {
    pub variable: String,
    pub stmt_id: usize,
    pub node_id: usize,
}

/// A definition of a variable: the statement id where the variable is written.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DefPoint {
    pub variable: String,
    pub stmt_id: usize,
    pub node_id: usize,
}

/// Def-Use chain: maps each definition to the set of uses it reaches.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefUseChain {
    pub chains: HashMap<DefPoint, HashSet<UsePoint>>,
}

impl DefUseChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_edge(&mut self, def: DefPoint, use_point: UsePoint) {
        self.chains.entry(def).or_default().insert(use_point);
    }

    #[must_use]
    pub fn uses_of(&self, def: &DefPoint) -> &HashSet<UsePoint> {
        static EMPTY: std::sync::OnceLock<HashSet<UsePoint>> = std::sync::OnceLock::new();
        self.chains
            .get(def)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }
}

/// Use-Def chain: maps each use to the set of definitions that may reach it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UseDefChain {
    pub chains: HashMap<UsePoint, HashSet<DefPoint>>,
}

impl UseDefChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_edge(&mut self, use_point: UsePoint, def: DefPoint) {
        self.chains.entry(use_point).or_default().insert(def);
    }

    #[must_use]
    pub fn defs_of(&self, use_point: &UsePoint) -> &HashSet<DefPoint> {
        static EMPTY: std::sync::OnceLock<HashSet<DefPoint>> = std::sync::OnceLock::new();
        self.chains
            .get(use_point)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }
}

/// Builds both `DefUseChain` and `UseDefChain` from reaching definitions results.
pub struct ChainBuilder;

impl ChainBuilder {
    /// Given a CFG and the reaching-definitions result, compute both chains.
    #[must_use]
    pub fn build(
        cfg: &Cfg<Statement>,
        rd_result: &DataFlowResult<BitSetLattice<Definition>>,
    ) -> (DefUseChain, UseDefChain) {
        let mut du = DefUseChain::new();
        let mut ud = UseDefChain::new();

        let mut stmt_to_node: HashMap<usize, usize> = HashMap::new();
        for (node_id, node) in cfg.nodes.iter().enumerate() {
            for stmt in &node.stmts {
                stmt_to_node.insert(stmt.id, node_id);
            }
        }

        for (node_id, node) in cfg.nodes.iter().enumerate() {
            // Group live definitions by variable name so each use looks up
            // its candidate defs in O(1) instead of doing a full O(|live_defs|)
            // linear scan per use (this was quadratic in def/use count on
            // large basic blocks: O(defs * uses)).
            let mut by_var: HashMap<String, Vec<Definition>> = HashMap::new();
            for def in rd_result.in_facts[node_id].set.clone() {
                by_var.entry(def.variable.clone()).or_default().push(def);
            }

            for stmt in &node.stmts {
                for use_var in &stmt.uses {
                    let use_pt = UsePoint {
                        variable: use_var.clone(),
                        stmt_id: stmt.id,
                        node_id,
                    };
                    if let Some(defs) = by_var.get(use_var) {
                        for def in defs {
                            let def_pt = DefPoint {
                                variable: def.variable.clone(),
                                stmt_id: def.stmt_id,
                                node_id: stmt_to_node
                                    .get(&def.stmt_id)
                                    .copied()
                                    .unwrap_or(node_id),
                            };
                            du.add_edge(def_pt.clone(), use_pt.clone());
                            ud.add_edge(use_pt.clone(), def_pt);
                        }
                    }
                }

                if let Some(ref def_var) = stmt.def {
                    by_var.remove(def_var);
                    by_var.entry(def_var.clone()).or_default().push(Definition {
                        variable: def_var.clone(),
                        stmt_id: stmt.id,
                    });
                }
            }
        }

        (du, ud)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Interprocedural data flow skeleton
// ────────────────────────────────────────────────────────────────────────────

/// Identifies a function in the interprocedural call graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
pub struct FunctionId(pub u64);

/// A node in the interprocedural call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    pub id: FunctionId,
    pub name: String,
    pub callees: Vec<FunctionId>,
}

/// Context for an interprocedural data flow computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterproceduralDataFlow<S: Clone + Debug, F: Lattice> {
    pub cfgs: HashMap<u64, Cfg<S>>,
    pub summaries: HashMap<u64, F>,
}

impl<S: Clone + Debug, F: Lattice> InterproceduralDataFlow<S, F> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cfgs: HashMap::new(),
            summaries: HashMap::new(),
        }
    }

    /// Register a function's CFG.
    pub fn register_function(&mut self, id: &FunctionId, cfg: Cfg<S>) {
        self.cfgs.insert(id.0, cfg);
    }

    /// Retrieve the summary (input-output fact) for a function, if computed.
    #[must_use]
    pub fn get_summary(&self, id: &FunctionId) -> Option<&F> {
        self.summaries.get(&id.0)
    }

    /// Store a computed summary.
    pub fn set_summary(&mut self, id: &FunctionId, fact: F) {
        self.summaries.insert(id.0, fact);
    }

    /// Compute summaries bottom-up over the call graph (simplified: no recursion).
    ///
    /// # Errors
    ///
    /// Returns `DataFlowError` if intraprocedural analysis fails for any function.
    pub fn compute_summaries<A>(
        &mut self,
        analysis: &A,
        call_order: &[FunctionId],
    ) -> Result<(), DataFlowError>
    where
        A: DataFlowAnalysis<Stmt = S, Fact = F>,
    {
        for fid in call_order {
            if let Some(cfg) = self.cfgs.get(&fid.0) {
                let cfg_clone = cfg.clone();
                let result = WorklistAlgorithm::run(analysis, &cfg_clone)?;
                let exit_fact = result
                    .out_facts
                    .get(cfg_clone.exit)
                    .ok_or(DataFlowError::NodeNotFound(cfg_clone.exit))?
                    .clone();
                self.summaries.insert(fid.0, exit_fact);
            }
        }
        Ok(())
    }
}

impl<S: Clone + Debug, F: Lattice> Default for InterproceduralDataFlow<S, F> {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers for building test CFGs
// ────────────────────────────────────────────────────────────────────────────

/// Build a linear CFG of single-statement blocks.
#[must_use]
pub fn linear_cfg(stmts: Vec<Statement>) -> Cfg<Statement> {
    let n = stmts.len();
    let nodes: Vec<CfgNode<Statement>> = stmts
        .into_iter()
        .enumerate()
        .map(|(i, s)| CfgNode {
            id: i,
            stmts: vec![s],
        })
        .collect();
    let successors: Vec<Vec<usize>> = (0..n)
        .map(|i| if i + 1 < n { vec![i + 1] } else { vec![] })
        .collect();
    Cfg::new(nodes, successors, 0, n.saturating_sub(1))
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitset_lattice_join_union() {
        let a: BitSetLattice<u32> = BitSetLattice::new([1, 2].into());
        let b: BitSetLattice<u32> = BitSetLattice::new([2, 3].into());
        let j = a.join(&b);
        assert!(j.contains(&1) && j.contains(&2) && j.contains(&3));
    }

    #[test]
    fn test_bitset_lattice_meet_intersection() {
        let a: BitSetLattice<u32> = BitSetLattice::new([1, 2].into());
        let b: BitSetLattice<u32> = BitSetLattice::new([2, 3].into());
        let m = a.meet(&b);
        assert!(!m.contains(&1) && m.contains(&2) && !m.contains(&3));
    }

    #[test]
    fn test_bitset_lattice_top_absorbs() {
        let top: BitSetLattice<u32> = BitSetLattice::top();
        let a: BitSetLattice<u32> = BitSetLattice::new([1].into());
        assert!(top.join(&a).is_top);
    }

    #[test]
    fn test_bitset_lattice_bottom_identity() {
        let bot: BitSetLattice<u32> = BitSetLattice::bottom();
        let a: BitSetLattice<u32> = BitSetLattice::new([1].into());
        assert_eq!(bot.join(&a), a);
    }

    #[test]
    fn test_bitset_lattice_leq() {
        let a: BitSetLattice<u32> = BitSetLattice::new([1].into());
        let b: BitSetLattice<u32> = BitSetLattice::new([1, 2].into());
        assert!(a.leq(&b));
        assert!(!b.leq(&a));
    }

    #[test]
    fn test_must_set_join_is_intersection() {
        let a = MustSet::new(["x".into(), "y".into()].into());
        let b = MustSet::new(["y".into(), "z".into()].into());
        let j = a.join(&b);
        assert!(j.set.contains("y"));
        assert!(!j.set.contains("x"));
        assert!(!j.set.contains("z"));
    }

    #[test]
    fn test_cfg_predecessors_computed() {
        let nodes = vec![
            CfgNode {
                id: 0,
                stmts: vec![],
            },
            CfgNode {
                id: 1,
                stmts: vec![],
            },
            CfgNode {
                id: 2,
                stmts: vec![],
            },
            CfgNode {
                id: 3,
                stmts: vec![],
            },
        ];
        let succs = vec![vec![1], vec![2, 3], vec![], vec![]];
        let cfg: Cfg<Statement> = Cfg::new(nodes, succs, 0, 2);
        assert_eq!(cfg.predecessors[1], vec![0]);
        assert!(cfg.predecessors[2].contains(&1));
        assert!(cfg.predecessors[3].contains(&1));
    }

    fn lva_cfg() -> Cfg<Statement> {
        let s0 = Statement::new(0, Some("x"), vec!["a", "b"]);
        let s1 = Statement::new(1, Some("y"), vec!["x", "c"]);
        let s2 = Statement::new(2, None, vec!["y"]);
        linear_cfg(vec![s0, s1, s2])
    }

    #[test]
    fn test_lva_runs_without_error() {
        let cfg = lva_cfg();
        let result = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap();
        assert_eq!(result.in_facts.len(), 3);
    }

    #[test]
    fn test_lva_y_live_at_block2_entry() {
        let cfg = lva_cfg();
        let result = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap();
        assert!(result.in_facts[2].contains(&"y".to_string()));
    }

    #[test]
    fn test_lva_x_live_at_block1_entry() {
        let cfg = lva_cfg();
        let result = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap();
        assert!(result.in_facts[1].contains(&"x".to_string()));
    }

    #[test]
    fn test_lva_x_not_live_at_block2_entry() {
        let cfg = lva_cfg();
        let result = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap();
        assert!(!result.in_facts[2].contains(&"x".to_string()));
    }

    fn rd_cfg() -> Cfg<Statement> {
        let s0 = Statement::new(0, Some("x"), vec![]);
        let s1 = Statement::new(1, Some("y"), vec!["x"]);
        let s2 = Statement::new(2, Some("x"), vec!["y"]);
        let s3 = Statement::new(3, None, vec!["x"]);
        linear_cfg(vec![s0, s1, s2, s3])
    }

    #[test]
    fn test_rd_runs() {
        let cfg = rd_cfg();
        let result = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
        assert_eq!(result.out_facts.len(), 4);
    }

    #[test]
    fn test_rd_first_def_reaches_block1() {
        let cfg = rd_cfg();
        let result = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
        assert!(
            result.in_facts[1].set.iter().any(|d| d.variable == "x"),
            "definition of x (stmt 0) should reach block 1"
        );
    }

    #[test]
    fn test_rd_second_def_kills_first() {
        let cfg = rd_cfg();
        let result = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
        let def0_reaches: bool = result.in_facts[3]
            .set
            .iter()
            .any(|d| d.variable == "x" && d.stmt_id == 0);
        assert!(
            !def0_reaches,
            "original x definition should be killed by stmt 2"
        );
    }

    #[test]
    fn test_available_expressions() {
        let universe: HashSet<String> = ["a+b".into(), "x*c".into()].into();
        let analysis = AvailableExpressions::new(universe);
        let s0 = Statement::new(0, Some("t"), vec!["a", "b"]).with_expr("a+b");
        let s1 = Statement::new(1, Some("u"), vec!["x", "c"]).with_expr("x*c");
        let cfg = linear_cfg(vec![s0, s1]);
        let result = WorklistAlgorithm::run(&analysis, &cfg).unwrap();
        assert!(result.out_facts[0].set.contains("a+b"));
    }

    #[test]
    fn test_available_expressions_kill() {
        let universe: HashSet<String> = ["a+b".into()].into();
        let analysis = AvailableExpressions::new(universe);
        let s0 = Statement::new(0, Some("t"), vec!["a", "b"]).with_expr("a+b");
        let s1 = Statement::new(1, Some("a"), vec![]);
        let cfg = linear_cfg(vec![s0, s1]);
        let result = WorklistAlgorithm::run(&analysis, &cfg).unwrap();
        assert!(!result.out_facts[1].set.contains("a+b"));
    }

    #[test]
    fn test_very_busy_expressions() {
        let universe: HashSet<String> = ["a+b".into()].into();
        let analysis = VeryBusyExpressions::new(universe);
        let s0 = Statement::new(0, None, vec!["a", "b"]).with_expr("a+b");
        let s1 = Statement::new(1, None, vec!["a", "b"]).with_expr("a+b");
        let nodes = vec![
            CfgNode {
                id: 0,
                stmts: vec![],
            },
            CfgNode {
                id: 1,
                stmts: vec![s0],
            },
            CfgNode {
                id: 2,
                stmts: vec![s1],
            },
            CfgNode {
                id: 3,
                stmts: vec![],
            },
        ];
        let succs = vec![vec![1, 2], vec![3], vec![3], vec![]];
        let cfg = Cfg::new(nodes, succs, 0, 3);
        let result = WorklistAlgorithm::run(&analysis, &cfg).unwrap();
        assert!(result.in_facts[0].set.contains("a+b"));
    }

    #[test]
    fn test_chain_builder_produces_edges() {
        let cfg = rd_cfg();
        let rd_result = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
        let (du, ud) = ChainBuilder::build(&cfg, &rd_result);
        let total = du.chains.values().map(std::collections::HashSet::len).sum::<usize>()
            + ud.chains.values().map(std::collections::HashSet::len).sum::<usize>();
        assert!(total > 0, "expected non-empty chains");
    }

    #[test]
    fn test_interprocedural_register_and_summarize() {
        let mut idf: InterproceduralDataFlow<Statement, BitSetLattice<Definition>> =
            InterproceduralDataFlow::new();
        let s0 = Statement::new(0, Some("x"), vec![]);
        let s1 = Statement::new(1, None, vec!["x"]);
        let cfg = linear_cfg(vec![s0, s1]);
        let fid = FunctionId(42);
        idf.register_function(&fid, cfg);
        idf.compute_summaries(&ReachingDefinitions, &[fid]).unwrap();
        assert!(idf.get_summary(&fid).is_some());
    }

    #[test]
    fn test_worklist_empty_cfg_error() {
        let cfg: Cfg<Statement> = Cfg::new(vec![], vec![], 0, 0);
        let result = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg);
        assert!(matches!(result, Err(DataFlowError::EmptyCfg)));
    }

    #[test]
    fn test_worklist_entry_out_of_range_does_not_panic() {
        // A non-empty CFG (n=2) with an out-of-range `entry` must return an
        // error rather than panicking on `in_facts[cfg.entry]`.
        let cfg: Cfg<Statement> = Cfg::new(
            vec![
                CfgNode { id: 0, stmts: vec![] },
                CfgNode { id: 1, stmts: vec![] },
            ],
            vec![vec![1], vec![]],
            99,
            1,
        );
        let result = WorklistAlgorithm::run(&ReachingDefinitions, &cfg);
        assert!(matches!(result, Err(DataFlowError::NodeNotFound(99))));
    }

    #[test]
    fn test_worklist_exit_out_of_range_does_not_panic() {
        // Same, but for a backward analysis indexing `out_facts[cfg.exit]`.
        let cfg: Cfg<Statement> = Cfg::new(
            vec![
                CfgNode { id: 0, stmts: vec![] },
                CfgNode { id: 1, stmts: vec![] },
            ],
            vec![vec![1], vec![]],
            0,
            42,
        );
        let result = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg);
        assert!(matches!(result, Err(DataFlowError::NodeNotFound(42))));
    }

    #[test]
    fn test_worklist_disconnected_node_uses_initial() {
        // Node 2 has no predecessors and is not the entry — it must fall
        // back to `analysis.initial()` rather than panicking on an empty
        // predecessor list indexed at [0].
        let cfg: Cfg<Statement> = Cfg::new(
            vec![
                CfgNode {
                    id: 0,
                    stmts: vec![Statement::new(0, Some("x"), vec![])],
                },
                CfgNode { id: 1, stmts: vec![] },
                CfgNode { id: 2, stmts: vec![] },
            ],
            vec![vec![], vec![], vec![]],
            0,
            0,
        );
        let result = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
        assert!(result.in_facts[2].set.is_empty());
    }

    #[test]
    fn test_worklist_manually_built_cfg_with_short_rows_does_not_panic() {
        // `Cfg`'s fields are public; a caller that builds one without going
        // through `Cfg::new` (e.g. from deserialized/partial data) can end
        // up with `predecessors`/`successors` shorter than `nodes`. This
        // must not panic.
        let cfg: Cfg<Statement> = Cfg {
            nodes: vec![
                CfgNode { id: 0, stmts: vec![] },
                CfgNode { id: 1, stmts: vec![] },
            ],
            successors: vec![vec![1]], // missing row for node 1
            predecessors: vec![],      // missing rows entirely
            entry: 0,
            exit: 1,
        };
        let result = WorklistAlgorithm::run(&ReachingDefinitions, &cfg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_convergence_single_node() {
        let s = Statement::new(0, Some("a"), vec![]);
        let cfg = linear_cfg(vec![s]);
        let result = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
        assert_eq!(result.out_facts[0].set.len(), 1);
    }

    #[test]
    fn test_lattice_value_is_const_and_as_const() {
        assert!(LatticeValue::Const(7).is_const());
        assert_eq!(LatticeValue::Const(7).as_const(), Some(7));
        assert!(!LatticeValue::Top.is_const());
        assert_eq!(LatticeValue::Top.as_const(), None);
        assert!(!LatticeValue::Bottom.is_const());
        assert_eq!(LatticeValue::Bottom.as_const(), None);
    }

    #[test]
    fn test_cfg_node_count() {
        let cfg = linear_cfg(vec![Statement::new(0, None, vec![]), Statement::new(1, None, vec![])]);
        assert_eq!(cfg.node_count(), 2);
    }

    #[test]
    fn test_def_use_chain_uses_of_and_defs_of_direct() {
        let mut du = DefUseChain::new();
        let mut ud = UseDefChain::new();
        let def = DefPoint { variable: "x".into(), stmt_id: 0, node_id: 0 };
        let use_pt = UsePoint { variable: "x".into(), stmt_id: 1, node_id: 0 };
        du.add_edge(def.clone(), use_pt.clone());
        ud.add_edge(use_pt.clone(), def.clone());

        assert!(du.uses_of(&def).contains(&use_pt));
        assert!(ud.defs_of(&use_pt).contains(&def));

        // Missing keys return an empty set rather than panicking.
        let missing_def = DefPoint { variable: "y".into(), stmt_id: 99, node_id: 0 };
        let missing_use = UsePoint { variable: "y".into(), stmt_id: 99, node_id: 0 };
        assert!(du.uses_of(&missing_def).is_empty());
        assert!(ud.defs_of(&missing_use).is_empty());
    }

    #[test]
    fn test_interprocedural_get_and_set_summary_direct() {
        let mut idf: InterproceduralDataFlow<Statement, BitSetLattice<u32>> =
            InterproceduralDataFlow::new();
        let fid = FunctionId(7);
        assert!(idf.get_summary(&fid).is_none());
        idf.set_summary(&fid, BitSetLattice::new([1, 2].into()));
        let summary = idf.get_summary(&fid).expect("summary was just set");
        assert!(summary.contains(&1));
        assert!(summary.contains(&2));
    }

    #[test]
    fn test_lva_branch_cfg() {
        let s0 = Statement::new(0, Some("x"), vec!["a"]);
        let s1 = Statement::new(1, Some("y"), vec!["x"]);
        let s2 = Statement::new(2, Some("z"), vec!["x"]);
        let s3 = Statement::new(3, None, vec!["y", "z"]);
        let nodes = vec![
            CfgNode {
                id: 0,
                stmts: vec![s0],
            },
            CfgNode {
                id: 1,
                stmts: vec![s1],
            },
            CfgNode {
                id: 2,
                stmts: vec![s2],
            },
            CfgNode {
                id: 3,
                stmts: vec![s3],
            },
        ];
        let succs = vec![vec![1, 2], vec![3], vec![3], vec![]];
        let cfg = Cfg::new(nodes, succs, 0, 3);
        let result = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap();
        assert!(result.out_facts[0].contains(&"x".to_string()));
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 1.  Liveness Analysis — backward dataflow, worklist-based
// ────────────────────────────────────────────────────────────────────────────
//
// Input representation
// --------------------
// Each element of `cfg_nodes` is a tuple
//   (bb_id, successors, gen_vars, kill_vars)
// where
//   bb_id      – unique u32 identifier for the basic block
//   successors – list of bb_ids that directly follow this block
//   gen_vars   – variables *used* before any definition in this block
//                (upward-exposed uses)
//   kill_vars  – variables *defined* in this block (kills liveness from below)
//
// Algorithm
// ---------
// We iterate until a fixpoint using a worklist (queue):
//
//   live_out[B] = ⋃  live_in[S]      (union over all successors S of B)
//   live_in[B]  = gen[B] ∪ (live_out[B] \ kill[B])
//
// Initialise live_in and live_out to ∅ for every block, then add every
// block to the worklist.  When live_in[B] changes, every predecessor of B
// is re-added to the worklist.
//
// Returns
// -------
// HashMap<u32, (Vec<u32>, Vec<u32>)>  →  bb_id → (live_in, live_out)
// Both sets are returned as sorted, deduplicated vectors for determinism.

/// (`bb_id`, successors, gen, kill) tuple describing a basic block for
/// dataflow analysis.
pub type LivenessCfgNode = (u32, Vec<u32>, Vec<u32>, Vec<u32>);
/// Per-block (`live_in`, `live_out`) sets, indexed by `bb_id`.
pub type LivenessSets = HashMap<u32, (Vec<u32>, Vec<u32>)>;

/// Compute live-in and live-out sets for each basic block using backward
/// dataflow on the (`bb_id`, successors, gen, kill) representation.
///
/// # Duplicate `bb_id`s
/// If `cfg_nodes` contains duplicate `bb_id`s, later entries silently
/// overwrite earlier ones in the internal id→index map (last write wins),
/// and the returned `LivenessSets` map will therefore have only one entry
/// per distinct `bb_id`, potentially discarding results for an earlier
/// duplicate's genuinely distinct gen/kill sets. Callers must ensure
/// `bb_id`s are unique within a single call.
#[must_use]
pub fn compute_liveness(
    cfg_nodes: &[LivenessCfgNode],
) -> LivenessSets {
    // ── index structures ──────────────────────────────────────────────────
    // Map bb_id → index in cfg_nodes for quick lookup.
    // FxHashMap prevents hash-collision DoS when bb_ids come from
    // attacker-controlled binary input.
    let id_to_idx: FxHashMap<u32, usize> = cfg_nodes
        .iter()
        .enumerate()
        .map(|(i, (id, _, _, _))| (*id, i))
        .collect();

    // Build predecessor lists: predecessor[bb_id] = set of ids that have
    // bb_id in their successor list.
    let mut predecessors: FxHashMap<u32, Vec<u32>> = cfg_nodes
        .iter()
        .map(|(id, _, _, _)| (*id, Vec::new()))
        .collect();
    for (id, succs, _, _) in cfg_nodes {
        for &s in succs {
            predecessors.entry(s).or_default().push(*id);
        }
    }

    // ── initialise live_in / live_out ─────────────────────────────────────
    let n = cfg_nodes.len();
    let mut live_in: Vec<HashSet<u32>> = vec![HashSet::new(); n];
    let mut live_out: Vec<HashSet<u32>> = vec![HashSet::new(); n];

    // ── worklist (all nodes, initially) ───────────────────────────────────
    let mut worklist: VecDeque<u32> = cfg_nodes.iter().map(|(id, _, _, _)| *id).collect();
    let mut in_worklist: HashSet<u32> = cfg_nodes.iter().map(|(id, _, _, _)| *id).collect();

    while let Some(bb_id) = worklist.pop_front() {
        in_worklist.remove(&bb_id);
        let Some(&idx) = id_to_idx.get(&bb_id) else { continue };
        let (_, succs, gen_vars, kill_vars) = &cfg_nodes[idx];

        // live_out[B] = ⋃ live_in[S]  for each successor S
        let new_out: HashSet<u32> = succs
            .iter()
            .filter_map(|s| id_to_idx.get(s))
            .flat_map(|&si| live_in[si].iter().copied())
            .collect();

        // live_in[B] = gen[B] ∪ (live_out[B] \ kill[B])
        let kill_set: HashSet<u32> = kill_vars.iter().copied().collect();
        let mut new_in: HashSet<u32> = new_out
            .iter()
            .filter(|v| !kill_set.contains(v))
            .copied()
            .collect();
        for &g in gen_vars {
            new_in.insert(g);
        }

        // Did live_in change?  If so, push predecessors back onto worklist.
        if new_in != live_in[idx] {
            live_in[idx] = new_in;
            if let Some(preds) = predecessors.get(&bb_id) {
                for &pred in preds {
                    if in_worklist.insert(pred) {
                        worklist.push_back(pred);
                    }
                }
            }
        }
        live_out[idx] = new_out;
    }

    // ── assemble result ───────────────────────────────────────────────────
    cfg_nodes
        .iter()
        .enumerate()
        .map(|(i, (id, _, _, _))| {
            let mut li: Vec<u32> = live_in[i].iter().copied().collect();
            let mut lo: Vec<u32> = live_out[i].iter().copied().collect();
            li.sort_unstable();
            lo.sort_unstable();
            (*id, (li, lo))
        })
        .collect()
}

/// Checked variant of [`compute_liveness`] that rejects duplicate `bb_id`s
/// instead of silently collapsing them to last-write-wins.
///
/// # Errors
/// Returns [`DataFlowError::DuplicateBbId`] if any `bb_id` appears more than
/// once in `cfg_nodes`.
pub fn compute_liveness_checked(
    cfg_nodes: &[LivenessCfgNode],
) -> Result<LivenessSets, DataFlowError> {
    if let Some(dup) = first_duplicate_bb_id(cfg_nodes.iter().map(|(id, _, _, _)| *id)) {
        return Err(DataFlowError::DuplicateBbId(dup));
    }
    Ok(compute_liveness(cfg_nodes))
}

// ────────────────────────────────────────────────────────────────────────────
// 2.  Reaching Definitions — forward dataflow, worklist-based
// ────────────────────────────────────────────────────────────────────────────
//
// Input  – same (bb_id, successors, gen_defs, kill_defs) tuple format.
//   gen_defs  – definition IDs generated (made available) by this block
//   kill_defs – definition IDs killed (overwritten) by this block
//
// Equations
// ---------
//   out[B] = gen[B] ∪ (in[B] \ kill[B])
//   in[B]  = ⋃  out[P]   for each predecessor P of B
//
// Returns
// -------
// HashMap<u32, (Vec<u32>, Vec<u32>)>  →  bb_id → (rd_in, rd_out)
// Both sorted, deduplicated.

/// Compute reaching-definition in/out sets for each basic block using forward
/// dataflow on the (`bb_id`, successors, gen, kill) representation.
///
/// # Duplicate `bb_id`s
/// As with [`compute_liveness`], duplicate `bb_id`s in `cfg_nodes` collapse
/// to a single entry (last write wins) in the internal id→index map. Callers
/// must ensure `bb_id`s are unique within a single call.
#[must_use]
pub fn compute_reaching_defs(
    cfg_nodes: &[LivenessCfgNode],
) -> LivenessSets {
    // ── index structures ──────────────────────────────────────────────────
    // FxHashMap prevents hash-collision DoS on attacker-controlled bb_ids.
    let id_to_idx: FxHashMap<u32, usize> = cfg_nodes
        .iter()
        .enumerate()
        .map(|(i, (id, _, _, _))| (*id, i))
        .collect();

    // Build predecessor lists (forward analysis needs them for meet).
    let mut predecessors: FxHashMap<u32, Vec<u32>> = cfg_nodes
        .iter()
        .map(|(id, _, _, _)| (*id, Vec::new()))
        .collect();
    for (id, succs, _, _) in cfg_nodes {
        for &s in succs {
            predecessors.entry(s).or_default().push(*id);
        }
    }

    // ── initialise rd_in / rd_out ─────────────────────────────────────────
    let n = cfg_nodes.len();
    let mut rd_in: Vec<HashSet<u32>> = vec![HashSet::new(); n];
    let mut rd_out: Vec<HashSet<u32>> = vec![HashSet::new(); n];

    // Initialise rd_out[B] = gen_defs[B] for all B (pre-seeding avoids extra
    // worklist passes for linear chains).
    for (i, (_, _, gen_defs, _)) in cfg_nodes.iter().enumerate() {
        rd_out[i] = gen_defs.iter().copied().collect();
    }

    // ── worklist ───────────────────────────────────────────────────────────
    let mut worklist: VecDeque<u32> = cfg_nodes.iter().map(|(id, _, _, _)| *id).collect();
    let mut in_worklist: HashSet<u32> = cfg_nodes.iter().map(|(id, _, _, _)| *id).collect();

    while let Some(bb_id) = worklist.pop_front() {
        in_worklist.remove(&bb_id);
        let Some(&idx) = id_to_idx.get(&bb_id) else { continue };
        let (_, _, gen_defs, kill_defs) = &cfg_nodes[idx];

        // in[B] = ⋃ out[P]
        let new_in: HashSet<u32> = predecessors
            .get(&bb_id)
            .into_iter()
            .flatten()
            .filter_map(|p| id_to_idx.get(p))
            .flat_map(|&pi| rd_out[pi].iter().copied())
            .collect();

        // out[B] = gen_defs[B] ∪ (in[B] \ kill_defs[B])
        let kill_set: HashSet<u32> = kill_defs.iter().copied().collect();
        let mut new_out: HashSet<u32> = new_in
            .iter()
            .filter(|v| !kill_set.contains(v))
            .copied()
            .collect();
        for &g in gen_defs {
            new_out.insert(g);
        }

        // Propagate change to successors.
        if new_out != rd_out[idx] {
            rd_out[idx] = new_out;
            let (_, succs, _, _) = &cfg_nodes[idx];
            for &succ in succs {
                if in_worklist.insert(succ) {
                    worklist.push_back(succ);
                }
            }
        }
        rd_in[idx] = new_in;
    }

    // ── assemble result ───────────────────────────────────────────────────
    cfg_nodes
        .iter()
        .enumerate()
        .map(|(i, (id, _, _, _))| {
            let mut ri: Vec<u32> = rd_in[i].iter().copied().collect();
            let mut ro: Vec<u32> = rd_out[i].iter().copied().collect();
            ri.sort_unstable();
            ro.sort_unstable();
            (*id, (ri, ro))
        })
        .collect()
}

/// Checked variant of [`compute_reaching_defs`] that rejects duplicate
/// `bb_id`s instead of silently collapsing them to last-write-wins.
///
/// # Errors
/// Returns [`DataFlowError::DuplicateBbId`] if any `bb_id` appears more than
/// once in `cfg_nodes`.
pub fn compute_reaching_defs_checked(
    cfg_nodes: &[LivenessCfgNode],
) -> Result<LivenessSets, DataFlowError> {
    if let Some(dup) = first_duplicate_bb_id(cfg_nodes.iter().map(|(id, _, _, _)| *id)) {
        return Err(DataFlowError::DuplicateBbId(dup));
    }
    Ok(compute_reaching_defs(cfg_nodes))
}

// ────────────────────────────────────────────────────────────────────────────
// 3a. Dead-code elimination and copy-propagation on LivenessCfgNode slices
// ────────────────────────────────────────────────────────────────────────────

/// Remove definitions whose left-hand-side variable is never live *after* the
/// block that defines it.
///
/// Each `LivenessCfgNode` is `(bb_id, successors, gen_vars, kill_vars)` where
/// `gen_vars` are upward-exposed uses and `kill_vars` are definitions.  A
/// kill (definition) of variable `v` in block `B` is *dead* when `v` does not
/// appear in `live_out[B]` — i.e. no successor path reads `v` before
/// redefining it.
///
/// The function returns a new node list with dead kills removed from each
/// block's `kill_vars`.  The `gen_vars` and CFG topology are unchanged.
#[must_use]
pub fn eliminate_dead_code(
    mut nodes: Vec<LivenessCfgNode>,
    liveness: &LivenessSets,
) -> Vec<LivenessCfgNode> {
    for (bb_id, _succs, _gen, kill) in &mut nodes {
        if let Some((_live_in, live_out)) = liveness.get(bb_id) {
            let live_out_set: HashSet<u32> = live_out.iter().copied().collect();
            kill.retain(|v| live_out_set.contains(v));
        }
    }
    nodes
}

/// Propagate copies by removing redundant kills (definitions) that are
/// immediately overwritten before being read.
///
/// Given reaching-definitions sets, a kill of variable `v` in block `B` is
/// redundant when `v` is already in `rd_in[B]` *and* `v` is not in `gen[B]`
/// (i.e. the block defines `v` without reading the incoming value first).
/// Removing such entries from `kill_vars` models copy-propagation by telling
/// downstream analyses that the earlier definition still flows through.
///
/// This is a conservative approximation suitable for abstract
/// `LivenessCfgNode` summaries; a full copy-propagation pass operates on the
/// concrete IR.
#[must_use]
pub fn copy_propagate(
    mut nodes: Vec<LivenessCfgNode>,
    reaching: &LivenessSets,
) -> Vec<LivenessCfgNode> {
    for (bb_id, _succs, r#gen, kill) in &mut nodes {
        if let Some((rd_in, _rd_out)) = reaching.get(bb_id) {
            let gen_set: HashSet<u32> = r#gen.iter().copied().collect();
            let rd_in_set: HashSet<u32> = rd_in.iter().copied().collect();
            // A kill entry is redundant when the same variable already arrives
            // via rd_in and the block never reads it first (not in gen).
            kill.retain(|v| !rd_in_set.contains(v) || gen_set.contains(v));
        }
    }
    nodes
}

// ────────────────────────────────────────────────────────────────────────────
// 3.  Constant Propagation — sparse flow-insensitive, lattice-based
// ────────────────────────────────────────────────────────────────────────────
//
// Lattice
// -------
//   Top     – the variable has not yet been seen / analysed (optimistic start)
//   Const(c)– the variable is always equal to the constant c
//   Bottom  – the variable may take more than one value (non-constant)
//
//   Top ⊑ Const(c) ⊑ Bottom
//   meet(Const(a), Const(b)) = if a==b { Const(a) } else { Bottom }
//
// Inputs
// ------
//   assignments : (var_id, const_value)  — every definition of var_id that
//                 has a constant right-hand side.  A var_id may appear
//                 multiple times if it has multiple constant assignments.
//   uses        : (use_site, var_id)     — reads of a variable at a use site.
//                 (Currently used to produce the complete variable universe;
//                  future interprocedural extensions can propagate through
//                  uses.)
//
// Algorithm
// ---------
// For each variable, meet together all constant values from its assignments.
// Any var_id that is *not* in `assignments` but appears in `uses` is treated
// as Bottom (unknown / non-constant).
//
// Returns HashMap<u32, LatticeValue>  →  var_id → lattice value.

/// Three-valued constant-propagation lattice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LatticeValue {
    /// Optimistic: no information yet.
    Top,
    /// Exactly one constant value.
    Const(i64),
    /// Pessimistic: more than one value, or a non-constant.
    Bottom,
}

impl LatticeValue {
    /// Meet (greatest lower bound) of two lattice values.
    ///
    /// ```text
    ///   meet(Top,      x)        = x
    ///   meet(x,        Top)      = x
    ///   meet(Const(a), Const(b)) = if a==b { Const(a) } else { Bottom }
    ///   meet(Bottom,   _)        = Bottom
    ///   meet(_,        Bottom)   = Bottom
    /// ```
    #[must_use]
    pub fn meet(a: &Self, b: &Self) -> Self {
        match (a, b) {
            (Self::Top, x) | (x, Self::Top) => x.clone(),
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Const(x), Self::Const(y)) => {
                if x == y {
                    Self::Const(*x)
                } else {
                    Self::Bottom
                }
            }
        }
    }

    /// Returns `true` if the value is a known constant.
    #[must_use]
    pub const fn is_const(&self) -> bool {
        matches!(self, Self::Const(_))
    }

    /// Extracts the constant value, if any.
    #[must_use]
    pub const fn as_const(&self) -> Option<i64> {
        if let Self::Const(c) = self {
            Some(*c)
        } else {
            None
        }
    }
}

/// Run sparse constant propagation over a set of assignments and uses.
///
/// # Arguments
/// * `assignments` – `(var_id, const_value)` pairs: each definition of a
///   variable whose RHS is a literal constant.
/// * `uses` – `(use_site_id, var_id)` pairs: every read of a variable.
///
/// # Returns
/// A map from variable id to its [`LatticeValue`].  Variables that appear
/// only in `uses` (but never in `assignments`) are mapped to `Bottom`.
#[must_use] 
pub fn propagate_constants(
    assignments: &[(u32, i64)],
    uses: &[(u32, u32)],
) -> HashMap<u32, LatticeValue> {
    // Collect all var_ids mentioned anywhere.
    let mut result: HashMap<u32, LatticeValue> = HashMap::new();

    // Seed every var that has at least one constant assignment.
    for &(var_id, const_val) in assignments {
        let entry = result.entry(var_id).or_insert(LatticeValue::Top);
        *entry = LatticeValue::meet(entry, &LatticeValue::Const(const_val));
    }

    // Every variable that appears in uses but has no constant assignment
    // is non-constant (Bottom).
    for &(_, var_id) in uses {
        result.entry(var_id).or_insert(LatticeValue::Bottom);
    }

    // Any variable that was assigned but also has a non-constant path
    // (i.e. appears in `uses` with no corresponding constant assignment)
    // stays at whatever the meet of its assignments computed.
    // No further fixpoint iteration needed for this sparse formulation.
    result
}

// ────────────────────────────────────────────────────────────────────────────
// 4.  SSA — phi-node insertion via iterated dominance frontiers
// ────────────────────────────────────────────────────────────────────────────
//
// Data structures
// ---------------

/// A phi-node produced during SSA construction.
///
/// `var_id` is the original (pre-SSA) variable.
/// `sources` lists `(predecessor_bb_id, ssa_version)` pairs — one per
/// control-flow predecessor of the block that contains this phi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhiNode {
    pub var_id: u32,
    /// (predecessor basic-block id, SSA version of the variable from that
    /// predecessor)
    pub sources: Vec<(u32, u32)>,
}

/// An SSA variable: the original variable id plus a renaming version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SsaVar {
    pub original_id: u32,
    pub version: u32,
}

// ────────────────────────────────────────────────────────────────────────────
// Dominator frontier computation (prerequisite for phi placement)
// ────────────────────────────────────────────────────────────────────────────

/// Compute the dominance frontier of every node in the CFG (entry-inclusive).
///
/// DF[n] = { y | ∃ predecessor x of y s.t. n dominates x,
///                but n does not strictly dominate y }
///
/// We use the standard O(n·e) algorithm that iterates over all edges once
/// and uses the idom array produced by [`compute_dominators`].
///
/// # Arguments
/// * `n` – number of nodes in the CFG (nodes are `0..n`).
/// * `successors` – adjacency list (indexed by node id).
/// * `idom` – immediate dominator array as returned by
///   [`compute_dominators`].  `idom[entry] == entry`.
///
/// # Returns
/// `Vec<Vec<usize>>` where `df[i]` is the dominance frontier of node `i`.
#[must_use]
pub fn compute_dominance_frontiers(
    n: usize,
    successors: &[Vec<usize>],
    idom: &[usize],
) -> Vec<Vec<usize>> {
    let mut df: Vec<HashSet<usize>> = vec![HashSet::new(); n];

    for (b, succs) in successors.iter().enumerate().take(n) {
        for &y in succs {
            if y >= n || idom[y] >= n {
                continue;
            }
            // Walk up the dominator tree from b until we reach idom[y].
            //
            // When `idom[y] == y` (y is the entry, which has no proper
            // idom), the walk instead runs to the top of the idom chain
            // *inclusive*: the entry dominates its predecessor b but does
            // not strictly dominate itself, so DF(entry) must contain the
            // entry when it is a loop header (a back edge targets it).
            // The old `while runner != idom[y]` form stopped one node
            // short in exactly that case, silently omitting the entry
            // from its own frontier — same bug class fixed in the cfg and
            // base crates' DominanceFrontier implementations.
            let stop = idom[y];
            let mut runner = b;
            let mut steps = 0usize;
            loop {
                // Guard against infinite loops caused by UNDEF sentinels or
                // malformed idom arrays.
                if steps >= n {
                    break;
                }
                if stop != y && runner == stop {
                    break;
                }
                df[runner].insert(y);
                if runner == idom[runner] {
                    // Top of the chain (entry, or an unreachable node's
                    // self-loop sentinel) — nothing further up.
                    break;
                }
                runner = idom[runner];
                steps += 1;
            }
        }
    }

    df.iter()
        .map(|s| {
            let mut v: Vec<usize> = s.iter().copied().collect();
            v.sort_unstable();
            v
        })
        .collect()
}

/// Insert phi-nodes at the iterated dominance frontier of each variable's
/// definition sites.
///
/// # Arguments
/// * `cfg` – `(bb_id, successors)` for each basic block.  Nodes are
///   identified by their position in the slice for dominance
///   computation, then mapped back to `bb_id` for the result.
/// * `defs` – `var_id → [list of basic block ids that define the variable]`.
///
/// # Returns
/// `HashMap<u32, Vec<u32>>` — `bb_id → [var_ids needing a phi-node]`.
///
/// # Algorithm (Cytron et al., simplified)
/// 1.  Compute immediate dominators (simple iterative RPO algorithm).
/// 2.  Compute dominance frontiers from the idom array.
/// 3.  For every variable, propagate phi placement through the iterated DF
///     using a worklist until a fixpoint is reached.
///
/// # Entry-node assumption
/// This entry point treats **`cfg[0]`** (the first slice element) as the
/// entry block, regardless of its `bb_id` value. Callers must order `cfg` so
/// the function's real entry block is first, or dominance (and therefore phi
/// placement) will be computed from the wrong root. If the entry block is not
/// necessarily first, use [`insert_phi_nodes_with_entry`] instead, which
/// takes an explicit `entry` `bb_id` parameter (matching the shape of
/// [`compute_dominators`]) and does not depend on slice order.
///
/// # Duplicate `bb_id`s
/// If `cfg` contains duplicate `bb_id`s, only the last occurrence is kept in
/// the id→index map used for dominance; earlier duplicates are silently
/// unreachable in the local graph. Callers must ensure `bb_id`s are unique.
#[must_use]
pub fn insert_phi_nodes<S: ::std::hash::BuildHasher>(
    cfg: &[(u32, Vec<u32>)],
    defs: &HashMap<u32, Vec<u32>, S>,
) -> HashMap<u32, Vec<u32>> {
    let Some((entry_id, _)) = cfg.first() else {
        return HashMap::new();
    };
    insert_phi_nodes_with_entry(cfg, *entry_id, defs)
}

/// Same as [`insert_phi_nodes`], but takes an explicit `entry` `bb_id`
/// instead of assuming `cfg[0]` is the entry block.
///
/// This is the preferred entry point when the caller's basic-block list is
/// not guaranteed to have the entry block first (e.g. blocks ordered by
/// address, or reconstructed from a map). If `entry` is not found among
/// `cfg`'s `bb_id`s, this falls back to treating `cfg[0]` as the entry (same
/// behavior as [`insert_phi_nodes`]), rather than silently computing
/// dominance from an arbitrary root.
///
/// # Duplicate `bb_id`s
/// Same caveat as [`insert_phi_nodes`]: duplicate `bb_id`s collapse to the
/// last occurrence in the id→index map. Callers must ensure `bb_id`s are
/// unique.
#[must_use]
pub fn insert_phi_nodes_with_entry<S: ::std::hash::BuildHasher>(
    cfg: &[(u32, Vec<u32>)],
    entry: u32,
    defs: &HashMap<u32, Vec<u32>, S>,
) -> HashMap<u32, Vec<u32>> {
    if cfg.is_empty() {
        return HashMap::new();
    }

    // Map bb_id (u32) → local index (usize) for the dom-tree algorithms.
    // FxHashMap prevents hash-collision DoS on attacker-controlled bb_ids.
    let id_to_local: FxHashMap<u32, usize> = cfg
        .iter()
        .enumerate()
        .map(|(i, (id, _))| (*id, i))
        .collect();

    // Build successor list in local indices.
    let n = cfg.len();
    let local_succs: Vec<Vec<usize>> = cfg
        .iter()
        .map(|(_, succs)| {
            succs
                .iter()
                .filter_map(|s| id_to_local.get(s).copied())
                .collect()
        })
        .collect();

    // Resolve the requested entry bb_id to a local index; fall back to 0
    // (cfg[0]) if it isn't present, rather than panicking or picking an
    // arbitrary node.
    let entry_local = id_to_local.get(&entry).copied().unwrap_or(0);

    // Compute immediate dominators from the resolved entry.
    let idom = compute_dominators(n, &local_succs, entry_local);

    // Compute dominance frontiers.
    let df = compute_dominance_frontiers(n, &local_succs, &idom);

    // ── phi-node placement per variable ───────────────────────────────────
    // phi_blocks[local_idx] = set of var_ids that need a phi at this block.
    let mut phi_blocks: Vec<HashSet<u32>> = vec![HashSet::new(); n];

    for (&var_id, def_bbs) in defs {
        // Worklist = initial set of defining blocks (as local indices).
        let mut worklist: VecDeque<usize> = def_bbs
            .iter()
            .filter_map(|bb| id_to_local.get(bb).copied())
            .collect();
        let mut has_phi: HashSet<usize> = HashSet::new();
        let mut in_worklist: HashSet<usize> = worklist.iter().copied().collect();

        while let Some(b) = worklist.pop_front() {
            in_worklist.remove(&b);
            for &y in &df[b] {
                if has_phi.insert(y) {
                    phi_blocks[y].insert(var_id);
                    // The phi itself is a new definition of var_id in block y,
                    // so y must also be added to the worklist.
                    if in_worklist.insert(y) {
                        worklist.push_back(y);
                    }
                }
            }
        }
    }

    // ── convert back to bb_id keys ────────────────────────────────────────
    cfg.iter()
        .enumerate()
        .filter_map(|(i, (bb_id, _))| {
            if phi_blocks[i].is_empty() {
                None
            } else {
                let mut vars: Vec<u32> = phi_blocks[i].iter().copied().collect();
                vars.sort_unstable();
                Some((*bb_id, vars))
            }
        })
        .collect()
}

/// Checked variant of [`insert_phi_nodes_with_entry`] that rejects duplicate
/// `bb_id`s instead of silently collapsing them to last-write-wins.
///
/// # Errors
/// Returns [`DataFlowError::DuplicateBbId`] if any `bb_id` appears more than
/// once in `cfg`.
pub fn insert_phi_nodes_with_entry_checked<S: ::std::hash::BuildHasher>(
    cfg: &[(u32, Vec<u32>)],
    entry: u32,
    defs: &HashMap<u32, Vec<u32>, S>,
) -> Result<HashMap<u32, Vec<u32>>, DataFlowError> {
    if let Some(dup) = first_duplicate_bb_id(cfg.iter().map(|(id, _)| *id)) {
        return Err(DataFlowError::DuplicateBbId(dup));
    }
    Ok(insert_phi_nodes_with_entry(cfg, entry, defs))
}

/// Checked variant of [`insert_phi_nodes`] that rejects duplicate `bb_id`s
/// instead of silently collapsing them to last-write-wins.
///
/// # Errors
/// Returns [`DataFlowError::DuplicateBbId`] if any `bb_id` appears more than
/// once in `cfg`.
pub fn insert_phi_nodes_checked<S: ::std::hash::BuildHasher>(
    cfg: &[(u32, Vec<u32>)],
    defs: &HashMap<u32, Vec<u32>, S>,
) -> Result<HashMap<u32, Vec<u32>>, DataFlowError> {
    let Some((entry_id, _)) = cfg.first() else {
        return Ok(HashMap::new());
    };
    insert_phi_nodes_with_entry_checked(cfg, *entry_id, defs)
}

// ────────────────────────────────────────────────────────────────────────────
// 5.  Dominator tree — simple iterative RPO algorithm (Cooper et al. 2001)
// ────────────────────────────────────────────────────────────────────────────
//
// Reference: "A Simple, Fast Dominance Algorithm" by Keith D. Cooper,
//            Timothy J. Harvey, and Ken Kennedy (2001).
//
// The algorithm processes nodes in reverse post-order (RPO), updating
// each node's immediate dominator until no changes occur.  It runs in
// O(n²) in the worst case but is very fast in practice on typical CFGs.
//
// `idom[i]` = immediate dominator of node `i`.
// `idom[entry] = entry` (entry dominates itself).

/// Compute a reverse-postorder (RPO) traversal of the CFG rooted at
/// `entry`.  Returns the node ids in RPO order.
///
/// Nodes not reachable from `entry` are omitted.
#[must_use] 
pub fn postorder(n: usize, succ: &[Vec<usize>], entry: usize) -> Vec<usize> {
    let mut visited = vec![false; n];
    let mut order = Vec::with_capacity(n);
    // Iterative DFS using an explicit stack.  Each stack frame is
    // (node, next_child_index).
    let mut stack: Vec<(usize, usize)> = Vec::with_capacity(n);

    if entry < n {
        visited[entry] = true;
        stack.push((entry, 0));
    }

    while let Some((node, child_idx)) = stack.last_mut() {
        let node = *node;
        // Guard against succ.len() < n — treat missing rows as empty.
        let empty: Vec<usize> = Vec::new();
        let children: &Vec<usize> = succ.get(node).unwrap_or(&empty);
        if *child_idx < children.len() {
            let child = children[*child_idx];
            *child_idx += 1;
            if child < n && !visited[child] {
                visited[child] = true;
                stack.push((child, 0));
            }
        } else {
            // All children visited — node is finished.
            stack.pop();
            order.push(node);
        }
    }

    order
}

fn dom_intersect(mut b1: usize, mut b2: usize, idom: &[usize], rpo_idx: &[usize]) -> usize {
    while b1 != b2 {
        while rpo_idx[b1] > rpo_idx[b2] {
            b1 = idom[b1];
        }
        while rpo_idx[b2] > rpo_idx[b1] {
            b2 = idom[b2];
        }
    }
    b1
}

/// Compute immediate dominators for every node reachable from `entry`.
///
/// Returns `idom` where `idom[i]` is the immediate dominator of node `i`.
/// For the entry node, `idom[entry] = entry`.
/// For unreachable nodes, `idom[i] = i` (self-loop sentinel).
///
/// # Arguments
/// * `n`          – number of nodes (ids are `0..n`).
/// * `successors` – adjacency list indexed by node id. **Shape:** outer
///   index is the source node id; inner `Vec<usize>` holds destination
///   ids reachable in one step. This is NOT a list of `[from, to]` edge
///   pairs and NOT a `{src: [dsts]}` dict — see
///   [`compute_dominators_from_edges`] if you have edge pairs instead.
/// * `entry`      – entry node id.
///
/// # JSON shape for MCP callers
/// ```json
/// { "n": 4, "successors": [[1, 2], [3], [3], []], "entry": 0 }
/// ```
/// Index 0 of `successors` is the successor list of node 0 (`0→1`, `0→2`).
///
/// # Out-of-range `entry`
/// If `entry >= n` (e.g. a malformed MCP request), every node is treated as
/// unreachable and `idom[i] = i` (self-loop sentinel) for all `i`. This
/// mirrors the existing "unreachable node" convention below and avoids an
/// index-out-of-bounds panic on attacker/user-controlled input.
///
/// # Panics
/// Does not panic on any input; `n == 0` and `entry >= n` are handled
/// explicitly above.
#[must_use]
pub fn compute_dominators(n: usize, successors: &[Vec<usize>], entry: usize) -> Vec<usize> {
    const UNDEF: usize = usize::MAX;
    let mut idom = vec![UNDEF; n];
    if n == 0 || entry >= n {
        // Fill self-loop sentinels so callers get a well-formed (if
        // meaningless) idom array instead of a panic.
        for (i, d) in idom.iter_mut().enumerate() {
            *d = i;
        }
        return idom;
    }
    idom[entry] = entry;

    // Build predecessor list.
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (src, succs) in successors.iter().enumerate() {
        for &dst in succs {
            if dst < n {
                preds[dst].push(src);
            }
        }
    }

    // Compute RPO and assign each node a unique RPO index.
    // The entry node gets the lowest index (0); other nodes are numbered
    // starting from 1 in the order they appear in reverse-postorder.
    let po = postorder(n, successors, entry);
    // Full RPO including entry (entry is last in postorder → first in RPO).
    let rpo_full: Vec<usize> = po.iter().rev().copied().collect();

    // rpo_idx[node] = position in rpo_full.  Unvisited nodes get UNDEF.
    let mut rpo_idx = vec![UNDEF; n];
    for (pos, &node) in rpo_full.iter().enumerate() {
        rpo_idx[node] = pos;
    }

    // rpo without the entry (we process every node except entry).
    let rpo: Vec<usize> = rpo_full.iter().skip(1).copied().collect();

    // ── Iterative fixpoint ────────────────────────────────────────────────
    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            // Consider only predecessors whose idom is already defined.
            let processed_preds: Vec<usize> = preds[b]
                .iter()
                .copied()
                .filter(|&p| idom[p] != UNDEF)
                .collect();

            if processed_preds.is_empty() {
                continue;
            }

            let mut new_idom = processed_preds[0];
            for &p in &processed_preds[1..] {
                new_idom = dom_intersect(p, new_idom, &idom, &rpo_idx);
            }

            if idom[b] != new_idom {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }

    // Fill in unreachable nodes with self-loop sentinels.
    for (i, d) in idom.iter_mut().enumerate().take(n) {
        if *d == UNDEF {
            *d = i;
        }
    }

    idom
}

/// Convenience wrapper accepting `[from, to]` edge pairs instead of an
/// adjacency list — for callers (e.g. MCP clients) that already serialize
/// CFGs as edge lists.
///
/// # JSON shape
/// ```json
/// { "n": 4, "edges": [[0,1],[0,2],[1,3],[2,3]], "entry": 0 }
/// ```
#[must_use]
pub fn compute_dominators_from_edges(
    n: usize,
    edges: &[[usize; 2]],
    entry: usize,
) -> Vec<usize> {
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    for &[from, to] in edges {
        if from < n {
            succ[from].push(to);
        }
    }
    compute_dominators(n, &succ, entry)
}

// ────────────────────────────────────────────────────────────────────────────
// Tests for the new algorithms
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod dataflow_algo_tests {
    use super::*;

    // ── Liveness ─────────────────────────────────────────────────────────

    /// Simple linear chain:  bb0 → bb1 → bb2
    ///   bb0: gen={}, kill={x}      (x = ...)
    ///   bb1: gen={x}, kill={y}     (y = x + ...)
    ///   bb2: gen={y}, kill={}      (use y)
    #[test]
    fn test_liveness_linear_chain() {
        let cfg = vec![
            (0u32, vec![1u32], vec![], vec![10u32]), // bb0: kill x(10)
            (1u32, vec![2u32], vec![10u32], vec![11u32]), // bb1: gen x(10), kill y(11)
            (2u32, vec![], vec![11u32], vec![]),     // bb2: gen y(11)
        ];
        let res = compute_liveness(&cfg);

        // x must be live at the entry of bb1 (used there)
        assert!(res[&1].0.contains(&10), "x live-in at bb1");
        // y must be live at entry of bb2
        assert!(res[&2].0.contains(&11), "y live-in at bb2");
        // x should NOT be live at entry of bb0 (killed there with no prior use)
        assert!(!res[&0].0.contains(&10), "x not live-in at bb0");
    }

    /// Diamond CFG:  bb0 → {bb1, bb2} → bb3
    ///   bb0: gen={}, kill={}
    ///   bb1: gen={v}, kill={}   (uses v)
    ///   bb2: gen={v}, kill={}   (uses v)
    ///   bb3: gen={}, kill={v}   (defines v — kills on exit)
    #[test]
    fn test_liveness_diamond() {
        let v = 42u32;
        let cfg = vec![
            (0u32, vec![1u32, 2u32], vec![], vec![]),
            (1u32, vec![3u32], vec![v], vec![]),
            (2u32, vec![3u32], vec![v], vec![]),
            (3u32, vec![], vec![], vec![v]),
        ];
        let res = compute_liveness(&cfg);
        // v must be live-out at bb0 (used in both successors)
        assert!(res[&0].1.contains(&v), "v live-out at bb0");
        // v must be live-in at bb1 and bb2
        assert!(res[&1].0.contains(&v));
        assert!(res[&2].0.contains(&v));
    }

    #[test]
    fn test_liveness_empty_cfg() {
        let res = compute_liveness(&[]);
        assert!(res.is_empty());
    }

    #[test]
    fn test_liveness_single_block() {
        // gen={a}, kill={b}  — a is live-in, b is NOT live-in (killed here)
        let cfg = vec![(0u32, vec![], vec![1u32], vec![2u32])];
        let res = compute_liveness(&cfg);
        assert!(res[&0].0.contains(&1));
        assert!(!res[&0].0.contains(&2));
    }

    // ── Duplicate bb_id hardening ──────────────────────────────────────

    #[test]
    fn test_liveness_checked_rejects_duplicate_bb_id() {
        let cfg = vec![
            (0u32, vec![1u32], vec![], vec![]),
            (1u32, vec![], vec![], vec![]),
            (1u32, vec![], vec![], vec![]), // duplicate bb_id 1
        ];
        let err = compute_liveness_checked(&cfg).unwrap_err();
        assert!(matches!(err, DataFlowError::DuplicateBbId(1)));
    }

    #[test]
    fn test_liveness_checked_accepts_unique_bb_ids() {
        let cfg = vec![
            (0u32, vec![1u32], vec![], vec![10u32]),
            (1u32, vec![], vec![10u32], vec![]),
        ];
        assert!(compute_liveness_checked(&cfg).is_ok());
    }

    #[test]
    fn test_reaching_defs_checked_rejects_duplicate_bb_id() {
        let cfg = vec![
            (5u32, vec![], vec![], vec![]),
            (5u32, vec![], vec![], vec![]), // duplicate bb_id 5
        ];
        let err = compute_reaching_defs_checked(&cfg).unwrap_err();
        assert!(matches!(err, DataFlowError::DuplicateBbId(5)));
    }

    #[test]
    fn test_reaching_defs_checked_accepts_unique_bb_ids() {
        let cfg = vec![(0u32, vec![], vec![], vec![])];
        assert!(compute_reaching_defs_checked(&cfg).is_ok());
    }

    #[test]
    fn test_insert_phi_nodes_checked_rejects_duplicate_bb_id() {
        let cfg = vec![
            (0u32, vec![1u32]),
            (1u32, vec![]),
            (1u32, vec![]), // duplicate bb_id 1
        ];
        let defs: HashMap<u32, Vec<u32>> = HashMap::new();
        let err = insert_phi_nodes_checked(&cfg, &defs).unwrap_err();
        assert!(matches!(err, DataFlowError::DuplicateBbId(1)));
    }

    #[test]
    fn test_insert_phi_nodes_with_entry_checked_rejects_duplicate_bb_id() {
        let cfg = vec![(0u32, vec![1u32]), (1u32, vec![]), (0u32, vec![])];
        let defs: HashMap<u32, Vec<u32>> = HashMap::new();
        let err = insert_phi_nodes_with_entry_checked(&cfg, 0, &defs).unwrap_err();
        assert!(matches!(err, DataFlowError::DuplicateBbId(0)));
    }

    #[test]
    fn test_insert_phi_nodes_checked_accepts_unique_bb_ids() {
        let cfg = vec![(0u32, vec![1u32, 2u32]), (1u32, vec![3u32]), (2u32, vec![3u32]), (3u32, vec![])];
        let mut defs: HashMap<u32, Vec<u32>> = HashMap::new();
        defs.insert(42u32, vec![1u32, 2u32]);
        let result = insert_phi_nodes_checked(&cfg, &defs).unwrap();
        assert_eq!(result.get(&3), Some(&vec![42u32]));
    }

    // ── Reaching Definitions ─────────────────────────────────────────────

    /// Linear chain where def 0 is killed by block 2.
    ///   bb0: gen={d0}, kill={}   (first def of x)
    ///   bb1: gen={d1}, kill={d0} (second def of x, kills d0)
    ///   bb2: gen={}, kill={}     (use only)
    #[test]
    fn test_reaching_defs_kill() {
        let cfg = vec![
            (0u32, vec![1u32], vec![100u32], vec![]),
            (1u32, vec![2u32], vec![101u32], vec![100u32]),
            (2u32, vec![], vec![], vec![]),
        ];
        let res = compute_reaching_defs(&cfg);
        // d0(100) should NOT reach bb2
        assert!(!res[&2].0.contains(&100), "d0 killed before bb2");
        // d1(101) should reach bb2
        assert!(res[&2].0.contains(&101), "d1 reaches bb2");
    }

    #[test]
    fn test_reaching_defs_merge() {
        // Diamond: two defs of the same variable, both should reach bb3.
        let cfg = vec![
            (0u32, vec![1u32, 2u32], vec![], vec![]),
            (1u32, vec![3u32], vec![10u32], vec![]),
            (2u32, vec![3u32], vec![20u32], vec![]),
            (3u32, vec![], vec![], vec![]),
        ];
        let res = compute_reaching_defs(&cfg);
        assert!(res[&3].0.contains(&10));
        assert!(res[&3].0.contains(&20));
    }

    #[test]
    fn test_reaching_defs_self_loop() {
        // Single block with a back-edge to itself.
        let cfg = vec![(0u32, vec![0u32], vec![5u32], vec![])];
        let res = compute_reaching_defs(&cfg);
        assert!(res[&0].0.contains(&5) || res[&0].1.contains(&5));
    }

    // ── Constant Propagation ─────────────────────────────────────────────

    #[test]
    fn test_cp_single_constant() {
        let assignments = [(1u32, 42i64)];
        let uses = [(99u32, 1u32)];
        let res = propagate_constants(&assignments, &uses);
        assert_eq!(res[&1], LatticeValue::Const(42));
    }

    #[test]
    fn test_cp_conflicting_constants() {
        // var 1 assigned both 10 and 20 → Bottom
        let assignments = [(1u32, 10i64), (1u32, 20i64)];
        let uses: &[(u32, u32)] = &[];
        let res = propagate_constants(&assignments, uses);
        assert_eq!(res[&1], LatticeValue::Bottom);
    }

    #[test]
    fn test_cp_same_constant_twice() {
        // var 1 assigned 7 twice → still Const(7)
        let assignments = [(1u32, 7i64), (1u32, 7i64)];
        let uses: &[(u32, u32)] = &[];
        let res = propagate_constants(&assignments, uses);
        assert_eq!(res[&1], LatticeValue::Const(7));
    }

    #[test]
    fn test_cp_use_only_variable_is_bottom() {
        // var 99 never assigned → Bottom
        let assignments: &[(u32, i64)] = &[];
        let uses = [(0u32, 99u32)];
        let res = propagate_constants(assignments, &uses);
        assert_eq!(res[&99], LatticeValue::Bottom);
    }

    #[test]
    fn test_cp_lattice_meet() {
        assert_eq!(
            LatticeValue::meet(&LatticeValue::Top, &LatticeValue::Const(5)),
            LatticeValue::Const(5)
        );
        assert_eq!(
            LatticeValue::meet(&LatticeValue::Const(3), &LatticeValue::Const(3)),
            LatticeValue::Const(3)
        );
        assert_eq!(
            LatticeValue::meet(&LatticeValue::Const(3), &LatticeValue::Const(4)),
            LatticeValue::Bottom
        );
        assert_eq!(
            LatticeValue::meet(&LatticeValue::Bottom, &LatticeValue::Const(9)),
            LatticeValue::Bottom
        );
    }

    // ── Dominators ───────────────────────────────────────────────────────

    /// Linear chain 0→1→2→3.  Dominators: idom[i] = i-1 for i>0.
    #[test]
    fn test_dominators_linear() {
        let succs = vec![vec![1], vec![2], vec![3], vec![]];
        let idom = compute_dominators(4, &succs, 0);
        assert_eq!(idom[0], 0);
        assert_eq!(idom[1], 0);
        assert_eq!(idom[2], 1);
        assert_eq!(idom[3], 2);
    }

    /// Diamond: 0→{1,2}, 1→3, 2→3.
    ///   idom[1]=0, idom[2]=0, idom[3]=0.
    #[test]
    fn test_dominators_diamond() {
        let succs = vec![vec![1, 2], vec![3], vec![3], vec![]];
        let idom = compute_dominators(4, &succs, 0);
        assert_eq!(idom[0], 0);
        assert_eq!(idom[1], 0);
        assert_eq!(idom[2], 0);
        assert_eq!(idom[3], 0);
    }

    /// Loop: 0→1, 1→{2,0} (back-edge).  idom[1]=0, idom[2]=1.
    #[test]
    fn test_dominators_loop() {
        let succs = vec![vec![1], vec![2, 0], vec![]];
        let idom = compute_dominators(3, &succs, 0);
        assert_eq!(idom[0], 0);
        assert_eq!(idom[1], 0);
        assert_eq!(idom[2], 1);
    }

    #[test]
    fn test_dominators_single_node() {
        let succs = vec![vec![]];
        let idom = compute_dominators(1, &succs, 0);
        assert_eq!(idom[0], 0);
    }

    #[test]
    fn test_dominators_entry_out_of_range_does_not_panic() {
        // Malformed input (e.g. a bogus MCP request): entry >= n. Must not
        // index-out-of-bounds panic; every node becomes its own sentinel.
        let succs = vec![vec![1], vec![2], vec![]];
        let idom = compute_dominators(3, &succs, 99);
        assert_eq!(idom, vec![0, 1, 2]);
    }

    #[test]
    fn test_dominators_from_edges_entry_out_of_range_does_not_panic() {
        let edges = [[0usize, 1], [1, 2]];
        let idom = compute_dominators_from_edges(3, &edges, 42);
        assert_eq!(idom, vec![0, 1, 2]);
    }

    #[test]
    fn test_dominators_unreachable_node_self_sentinel() {
        // Node 2 has no incoming edges at all: idom[2] must stay the
        // self-loop sentinel rather than an arbitrary/garbage value.
        let succs = vec![vec![1], vec![], vec![]];
        let idom = compute_dominators(3, &succs, 0);
        assert_eq!(idom[0], 0);
        assert_eq!(idom[1], 0);
        assert_eq!(idom[2], 2, "unreachable node must self-dominate");
    }

    /// Same diamond as `test_dominators_diamond`, but expressed as edge
    /// pairs via the `[from, to]` convenience wrapper.
    #[test]
    fn test_dominators_from_edges_diamond() {
        let edges = [[0, 1], [0, 2], [1, 3], [2, 3]];
        let idom = compute_dominators_from_edges(4, &edges, 0);
        assert_eq!(idom[0], 0);
        assert_eq!(idom[1], 0);
        assert_eq!(idom[2], 0);
        assert_eq!(idom[3], 0);
    }

    #[test]
    fn test_dominators_from_edges_matches_adjacency_form() {
        // The edge-list and adjacency-list entry points must agree for the
        // same graph.
        let succs = vec![vec![1usize], vec![2, 0], vec![]];
        let edges = [[0, 1], [1, 2], [1, 0]];
        let from_adj = compute_dominators(3, &succs, 0);
        let from_edges = compute_dominators_from_edges(3, &edges, 0);
        assert_eq!(from_adj, from_edges);
    }

    #[test]
    fn test_dominators_from_edges_out_of_range_from_ignored() {
        // An edge whose `from` is out of range must be ignored rather than
        // panicking (guards against malformed MCP input).
        let edges = [[0, 1], [5, 2]];
        let idom = compute_dominators_from_edges(2, &edges, 0);
        assert_eq!(idom.len(), 2);
        assert_eq!(idom[0], 0);
        assert_eq!(idom[1], 0);
    }

    // ── Postorder ────────────────────────────────────────────────────────

    #[test]
    fn test_postorder_linear() {
        let succs = vec![vec![1usize], vec![2], vec![]];
        let po = postorder(3, &succs, 0);
        // In a linear chain the postorder is [2, 1, 0].
        assert_eq!(po, vec![2, 1, 0]);
    }

    #[test]
    fn test_postorder_diamond() {
        let succs = vec![vec![1usize, 2], vec![3], vec![3], vec![]];
        let po = postorder(4, &succs, 0);
        // 3 must appear before 1 and 2 which must appear before 0.
        let pos: HashMap<usize, usize> = po.iter().enumerate().map(|(i, &n)| (n, i)).collect();
        assert!(pos[&3] < pos[&1]);
        assert!(pos[&3] < pos[&2]);
        assert!(pos[&1] < pos[&0] || pos[&2] < pos[&0]);
    }

    // ── SSA / Phi-node Insertion ──────────────────────────────────────────

    /// Diamond CFG:  bb0 → {bb1, bb2} → bb3
    /// Variable v is defined in bb1 and bb2.
    /// The dominance frontier of both bb1 and bb2 includes bb3.
    /// Therefore a phi-node for v should be inserted at bb3.
    #[test]
    fn test_phi_insertion_diamond() {
        let cfg = vec![
            (0u32, vec![1u32, 2u32]),
            (1u32, vec![3u32]),
            (2u32, vec![3u32]),
            (3u32, vec![]),
        ];
        let mut defs: HashMap<u32, Vec<u32>> = HashMap::new();
        defs.insert(99u32, vec![1u32, 2u32]); // var 99 defined in bb1 and bb2
        let phi = insert_phi_nodes(&cfg, &defs);
        assert!(
            phi.get(&3u32).is_some_and(|v| v.contains(&99u32)),
            "phi for var 99 expected at bb3"
        );
    }

    /// Linear chain: bb0 → bb1 → bb2.
    /// A variable defined only in bb0 has no join point → no phis.
    #[test]
    fn test_phi_insertion_no_join() {
        let cfg = vec![(0u32, vec![1u32]), (1u32, vec![2u32]), (2u32, vec![])];
        let mut defs: HashMap<u32, Vec<u32>> = HashMap::new();
        defs.insert(1u32, vec![0u32]);
        let phi = insert_phi_nodes(&cfg, &defs);
        // No dominance frontiers in a linear chain → no phis.
        assert!(phi.is_empty() || phi.values().all(std::vec::Vec::is_empty));
    }

    /// Loop: bb0 → bb1 → {bb2, bb0}.
    /// Variable defined in bb1 — its dominance frontier includes bb1
    /// (back-edge from bb1).  A phi-node should appear at bb1.
    #[test]
    fn test_phi_insertion_loop() {
        let cfg = vec![
            (0u32, vec![1u32]),
            (1u32, vec![2u32, 0u32]), // back-edge to bb0
            (2u32, vec![]),
        ];
        let mut defs: HashMap<u32, Vec<u32>> = HashMap::new();
        // var defined in bb1; bb1's own back-edge creates a DF entry.
        defs.insert(77u32, vec![1u32]);
        // This test just ensures no panic and returns a valid map.
        let _phi = insert_phi_nodes(&cfg, &defs);
    }

    #[test]
    fn test_phi_insertion_empty_cfg() {
        let cfg: Vec<(u32, Vec<u32>)> = vec![];
        let defs: HashMap<u32, Vec<u32>> = HashMap::new();
        let phi = insert_phi_nodes(&cfg, &defs);
        assert!(phi.is_empty());
    }

    /// Same diamond as `test_phi_insertion_diamond`, but with the entry block
    /// NOT first in the slice — `insert_phi_nodes` (which assumes `cfg[0]` is
    /// the entry) would compute dominance from the wrong root here, while
    /// `insert_phi_nodes_with_entry` must still get it right via the
    /// explicit `entry` parameter.
    #[test]
    fn test_phi_insertion_with_entry_out_of_order() {
        let cfg = vec![
            (3u32, vec![]),
            (1u32, vec![3u32]),
            (2u32, vec![3u32]),
            (0u32, vec![1u32, 2u32]), // real entry, placed last in the slice
        ];
        let mut defs: HashMap<u32, Vec<u32>> = HashMap::new();
        defs.insert(99u32, vec![1u32, 2u32]);
        let phi = insert_phi_nodes_with_entry(&cfg, 0, &defs);
        assert!(
            phi.get(&3u32).is_some_and(|v| v.contains(&99u32)),
            "phi for var 99 expected at bb3 even with entry out of slice order"
        );
    }

    /// If the requested `entry` `bb_id` isn't present in `cfg`, fall back to
    /// `cfg[0]` (matching `insert_phi_nodes`) instead of panicking.
    #[test]
    fn test_phi_insertion_with_entry_unknown_falls_back_to_first() {
        let cfg = vec![
            (0u32, vec![1u32, 2u32]),
            (1u32, vec![3u32]),
            (2u32, vec![3u32]),
            (3u32, vec![]),
        ];
        let mut defs: HashMap<u32, Vec<u32>> = HashMap::new();
        defs.insert(99u32, vec![1u32, 2u32]);
        let phi = insert_phi_nodes_with_entry(&cfg, 12345, &defs);
        assert!(phi.get(&3u32).is_some_and(|v| v.contains(&99u32)));
    }

    /// `insert_phi_nodes` and `insert_phi_nodes_with_entry(cfg, cfg[0].0, ..)`
    /// must agree, since the latter is the generalization of the former.
    #[test]
    fn test_phi_insertion_with_entry_matches_default_entry_point() {
        let cfg = vec![
            (0u32, vec![1u32, 2u32]),
            (1u32, vec![3u32]),
            (2u32, vec![3u32]),
            (3u32, vec![]),
        ];
        let mut defs: HashMap<u32, Vec<u32>> = HashMap::new();
        defs.insert(99u32, vec![1u32, 2u32]);
        let a = insert_phi_nodes(&cfg, &defs);
        let b = insert_phi_nodes_with_entry(&cfg, 0, &defs);
        assert_eq!(a, b);
    }

    // ── Dominance Frontiers ───────────────────────────────────────────────

    #[test]
    fn test_dom_frontier_diamond() {
        // 0→{1,2}, 1→3, 2→3.  idom = [0,0,0,0].
        let succs = vec![vec![1usize, 2], vec![3], vec![3], vec![]];
        let idom = compute_dominators(4, &succs, 0);
        let df = compute_dominance_frontiers(4, &succs, &idom);
        // DF[1] = {3}, DF[2] = {3}.
        assert!(df[1].contains(&3));
        assert!(df[2].contains(&3));
        // DF[0] should be empty (entry dominates all).
        assert!(df[0].is_empty());
        // DF[3] should be empty.
        assert!(df[3].is_empty());
    }

    #[test]
    fn test_dom_frontier_empty_cfg() {
        // n == 0: must return an empty Vec, not panic on idom indexing.
        let succs: Vec<Vec<usize>> = vec![];
        let idom: Vec<usize> = vec![];
        let df = compute_dominance_frontiers(0, &succs, &idom);
        assert!(df.is_empty());
    }

    #[test]
    fn test_cp_empty_inputs() {
        // No assignments and no uses at all: must return an empty map, not panic.
        let res = propagate_constants(&[], &[]);
        assert!(res.is_empty());
    }

    #[test]
    fn test_dom_frontier_linear() {
        // 0→1→2→3.  All idoms sequential.
        let succs = vec![vec![1usize], vec![2], vec![3], vec![]];
        let idom = compute_dominators(4, &succs, 0);
        let df = compute_dominance_frontiers(4, &succs, &idom);
        // Linear chains have no join points → all frontiers empty.
        for d in &df {
            assert!(d.is_empty());
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DataFlowAnalysisPass — AnalysisPass implementation
// ────────────────────────────────────────────────────────────────────────────

use rustre_analysis::{AnalysisConfig, AnalysisError, AnalysisKind, AnalysisPass, AnalysisResult};
use rustre_core::binary_view::BinaryView;

/// An [`AnalysisPass`] that runs the worklist-based data flow framework over
/// all functions in the binary view.
///
/// For each function the pass builds a single-block CFG (a placeholder until
/// a full CFG lifting layer is wired up) and runs [`LiveVariableAnalysis`]
/// to verify the framework operates end-to-end.
pub struct DataFlowAnalysisPass;

impl DataFlowAnalysisPass {
    /// Create a new `DataFlowAnalysisPass`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DataFlowAnalysisPass {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DataFlowAnalysisPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataFlowAnalysisPass").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AnalysisPass for DataFlowAnalysisPass {
    fn name(&self) -> &'static str {
        "dataflow_analysis"
    }

    fn kind(&self) -> AnalysisKind {
        AnalysisKind::DataFlow
    }

    fn description(&self) -> &'static str {
        "Worklist-based data flow analysis (liveness, reaching defs, constant propagation)"
    }

    async fn run(
        &self,
        view: &BinaryView,
        _config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        let start = std::time::Instant::now();

        // Collect function entry addresses from the binary view.
        let function_addrs: Vec<u64> = {
            let table = view.functions.read();
            table.iter_functions().map(|f| f.address.as_u64()).collect()
        };

        let functions_found = function_addrs.len();

        // For each function, build a minimal single-statement CFG and run
        // the worklist liveness analysis.  This validates the end-to-end
        // pipeline; a richer CFG builder will replace this placeholder once
        // the disassembly/lifting layer is integrated.
        let mut warnings: Vec<String> = Vec::new();

        for addr in &function_addrs {
            // Placeholder statement representing the function body.
            let stmt = Statement::new(0, Some("ret"), vec!["arg0"]);
            let cfg = linear_cfg(vec![stmt]);

            match WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg) {
                Ok(_result) => {
                    // Analysis succeeded; results could be stored to a DB
                    // or event bus here.
                }
                Err(e) => {
                    warnings.push(format!("dataflow error at 0x{addr:x}: {e}"));
                }
            }
        }

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        Ok(AnalysisResult {
            kind: AnalysisKind::DataFlow,
            functions_found,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms,
            warnings,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Backward caller-trace: walk call-graph edges in reverse
// ────────────────────────────────────────────────────────────────────────────

/// A single node entry in a backward-trace level.
///
/// `addr` is the function address; `name` is an optional symbolic name
/// (always `None` from the pure graph walk in [`trace_callers_backward`];
/// callers may post-process to attach symbols).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NodeRec {
    /// Function address.
    pub addr: u64,
    /// Optional symbolic name for the function at `addr`.
    pub name: Option<String>,
}

/// Result of [`trace_callers_backward`].
///
/// `levels[0]` contains the direct callers of the traced address,
/// `levels[1]` their callers, and so on up to the requested `hops` limit
/// (clamped at [`MAX_BACKWARD_HOPS`]). `total` is the number of distinct
/// nodes discovered across all levels (the origin itself is not counted).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct BackwardTrace {
    /// Per-hop levels; `levels[i]` contains callers `i + 1` edges away.
    pub levels: Vec<Vec<NodeRec>>,
    /// Total distinct nodes found (sum of all level lengths).
    pub total: usize,
}

/// Maximum number of backward hops permitted by [`trace_callers_backward`].
pub const MAX_BACKWARD_HOPS: usize = 10;

/// Walk a call-graph backwards from `addr` up to `hops` hops.
///
/// `edges` is a flat slice of `(caller, callee)` address pairs.  The function
/// is deliberately decoupled from any binary loader so it can be exercised in
/// unit tests with synthetic graphs.
///
/// Nodes already seen at an earlier level are not revisited (BFS dedup).
///
/// # Arguments
/// * `addr`  – the starting function address (callee we are tracing back from).
/// * `hops`  – maximum number of backward hops (levels beyond the origin).
/// * `edges` – call-graph edges as `(caller_addr, callee_addr)` pairs.
///
/// # Returns
/// A [`BackwardTrace`] whose `levels[0]` are direct callers and `levels.len()`
/// is at most `min(hops, MAX_BACKWARD_HOPS)` (less if the graph runs out).
#[must_use]
pub fn trace_callers_backward(addr: u64, hops: usize, edges: &[(u64, u64)]) -> BackwardTrace {
    let hops = hops.min(MAX_BACKWARD_HOPS);
    if hops == 0 {
        return BackwardTrace::default();
    }

    // Build a reverse adjacency map: callee → set of callers.
    let mut callers_of: HashMap<u64, Vec<u64>> = HashMap::new();
    for &(caller, callee) in edges {
        callers_of.entry(callee).or_default().push(caller);
    }

    let mut visited: HashSet<u64> = HashSet::new();
    visited.insert(addr);

    let mut levels: Vec<Vec<NodeRec>> = Vec::with_capacity(hops);
    let mut frontier: Vec<u64> = vec![addr];

    for _ in 0..hops {
        let mut next_frontier: Vec<u64> = Vec::new();
        let mut level: Vec<NodeRec> = Vec::new();

        for node_addr in &frontier {
            if let Some(callers) = callers_of.get(node_addr) {
                for &caller in callers {
                    if visited.insert(caller) {
                        level.push(NodeRec { addr: caller, name: None });
                        next_frontier.push(caller);
                    }
                }
            }
        }

        // Sort for deterministic output regardless of HashMap iteration order.
        level.sort_by_key(|r| r.addr);

        if level.is_empty() {
            break;
        }

        levels.push(level);
        frontier = next_frontier;
    }

    let total = levels.iter().map(Vec::len).sum();
    BackwardTrace { levels, total }
}

/// Result of [`trace_callees_forward`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ForwardTrace {
    /// Per-hop levels; `levels[i]` contains callees `i + 1` edges away.
    pub levels: Vec<Vec<NodeRec>>,
    /// Total distinct nodes found (sum of all level lengths).
    pub total: usize,
}

/// Maximum number of forward hops permitted by [`trace_callees_forward`].
pub const MAX_FORWARD_HOPS: usize = 10;

/// Walk a call-graph forward from `addr` up to `hops` hops.
///
/// `edges` is a flat slice of `(caller, callee)` address pairs.
///
/// # Arguments
/// * `addr`  – the starting function address (caller we are tracing forward from).
/// * `hops`  – maximum number of forward hops (levels beyond the origin).
/// * `edges` – call-graph edges as `(caller_addr, callee_addr)` pairs.
///
/// # Returns
/// A [`ForwardTrace`] whose `levels[0]` are direct callees and `levels.len()`
/// is at most `min(hops, MAX_FORWARD_HOPS)`.
#[must_use]
pub fn trace_callees_forward(addr: u64, hops: usize, edges: &[(u64, u64)]) -> ForwardTrace {
    let hops = hops.min(MAX_FORWARD_HOPS);
    if hops == 0 {
        return ForwardTrace::default();
    }

    let mut callees_of: HashMap<u64, Vec<u64>> = HashMap::new();
    for &(caller, callee) in edges {
        callees_of.entry(caller).or_default().push(callee);
    }

    let mut visited: HashSet<u64> = HashSet::new();
    visited.insert(addr);

    let mut levels: Vec<Vec<NodeRec>> = Vec::with_capacity(hops);
    let mut frontier: Vec<u64> = vec![addr];

    for _ in 0..hops {
        let mut next_frontier: Vec<u64> = Vec::new();
        let mut level: Vec<NodeRec> = Vec::new();

        for node_addr in &frontier {
            if let Some(callees) = callees_of.get(node_addr) {
                for &callee in callees {
                    if visited.insert(callee) {
                        level.push(NodeRec { addr: callee, name: None });
                        next_frontier.push(callee);
                    }
                }
            }
        }

        level.sort_by_key(|r| r.addr);

        if level.is_empty() {
            break;
        }

        levels.push(level);
        frontier = next_frontier;
    }

    let total = levels.iter().map(Vec::len).sum();
    ForwardTrace { levels, total }
}

#[cfg(test)]
mod trace_callees_tests {
    use super::*;

    fn three_level_edges() -> Vec<(u64, u64)> {
        vec![
            (0x100, 0x200), // child calls parent
            (0x200, 0x300), // parent calls grandparent
        ]
    }

    #[test]
    fn test_trace_empty_when_hops_zero() {
        let edges = three_level_edges();
        let ft = trace_callees_forward(0x100, 0, &edges);
        assert!(ft.levels.is_empty());
        assert_eq!(ft.total, 0);
    }

    #[test]
    fn test_trace_one_hop_finds_callee() {
        let edges = three_level_edges();
        let ft = trace_callees_forward(0x100, 1, &edges);
        assert_eq!(ft.levels.len(), 1);
        assert_eq!(ft.levels[0].len(), 1);
        assert_eq!(ft.levels[0][0].addr, 0x200);
        assert_eq!(ft.levels[0][0].name, None);
        assert_eq!(ft.total, 1);
    }

    #[test]
    fn test_trace_two_hops_finds_grand_callee() {
        let edges = three_level_edges();
        let ft = trace_callees_forward(0x100, 2, &edges);
        assert_eq!(ft.levels.len(), 2);
        assert_eq!(ft.levels[0][0].addr, 0x200);
        assert_eq!(ft.levels[1].len(), 1);
        assert_eq!(ft.levels[1][0].addr, 0x300);
        assert_eq!(ft.total, 2);
    }

    #[test]
    fn test_trace_stops_early_when_no_more_callees() {
        let edges = three_level_edges();
        let ft = trace_callees_forward(0x100, 10, &edges);
        assert_eq!(ft.levels.len(), 2);
        assert_eq!(ft.total, 2);
    }

    #[test]
    fn test_trace_no_callees_returns_empty() {
        let ft = trace_callees_forward(0xDEAD, 5, &[]);
        assert!(ft.levels.is_empty());
        assert_eq!(ft.total, 0);
    }

    #[test]
    fn test_trace_dedup_multiple_callees_same_node() {
        let edges: Vec<(u64, u64)> = vec![
            (0x100, 0x200),
            (0x100, 0x201),
            (0x200, 0x300),
            (0x201, 0x300),
        ];
        let ft = trace_callees_forward(0x100, 2, &edges);
        assert_eq!(ft.levels[0].len(), 2);
        assert_eq!(ft.levels[1].len(), 1);
        assert_eq!(ft.total, 3);
    }

    #[test]
    fn test_trace_direct_callees_fanout() {
        let edges = [(10u64, 1u64), (10, 2), (10, 3)];
        let ft = trace_callees_forward(10, 1, &edges);
        assert_eq!(ft.levels.len(), 1);
        assert_eq!(ft.total, 3);
        let got: Vec<u64> = ft.levels[0].iter().map(|n| n.addr).collect();
        assert_eq!(got, vec![1, 2, 3]);
        assert!(ft.levels[0].iter().all(|n| n.name.is_none()));
    }

    #[test]
    fn test_trace_cycle_does_not_loop() {
        let edges = [(4u64, 3u64), (3, 2), (2, 1), (1, 1), (1, 2)];
        let ft = trace_callees_forward(4, 5, &edges);
        assert_eq!(ft.levels.len(), 3);
        assert_eq!(ft.levels[0].iter().map(|n| n.addr).collect::<Vec<_>>(), vec![3]);
        assert_eq!(ft.levels[1].iter().map(|n| n.addr).collect::<Vec<_>>(), vec![2]);
        assert_eq!(ft.levels[2].iter().map(|n| n.addr).collect::<Vec<_>>(), vec![1]);
        assert_eq!(ft.total, 3);
    }

    #[test]
    fn test_trace_hops_clamped_at_max() {
        let chain: Vec<(u64, u64)> = (0..20u64).map(|i| (i, i + 1)).collect();
        let ft = trace_callees_forward(0, 1_000, &chain);
        assert_eq!(ft.levels.len(), MAX_FORWARD_HOPS);
        assert_eq!(ft.total, MAX_FORWARD_HOPS);
        assert_eq!(
            ft.levels.last().unwrap()[0].addr,
            MAX_FORWARD_HOPS as u64
        );
    }
}

#[cfg(test)]
mod trace_callers_tests {
    use super::*;

    /// Build a synthetic 3-level chain:
    ///
    ///   grandparent (0x300) → parent (0x200) → child (0x100)
    ///
    /// Tracing backward from 0x100 with hops=2 should yield:
    ///   level 0: [0x100]
    ///   level 1: [0x200]
    ///   level 2: [0x300]
    fn three_level_edges() -> Vec<(u64, u64)> {
        vec![
            (0x200, 0x100), // parent calls child
            (0x300, 0x200), // grandparent calls parent
        ]
    }

    #[test]
    fn test_trace_empty_when_hops_zero() {
        let edges = three_level_edges();
        let bt = trace_callers_backward(0x100, 0, &edges);
        assert!(bt.levels.is_empty());
        assert_eq!(bt.total, 0);
    }

    #[test]
    fn test_trace_one_hop_finds_parent() {
        let edges = three_level_edges();
        let bt = trace_callers_backward(0x100, 1, &edges);
        assert_eq!(bt.levels.len(), 1, "levels[0] = direct callers");
        assert_eq!(bt.levels[0].len(), 1);
        assert_eq!(bt.levels[0][0].addr, 0x200);
        assert_eq!(bt.levels[0][0].name, None);
        assert_eq!(bt.total, 1);
    }

    #[test]
    fn test_trace_two_hops_finds_grandparent() {
        let edges = three_level_edges();
        let bt = trace_callers_backward(0x100, 2, &edges);
        assert_eq!(bt.levels.len(), 2);
        assert_eq!(bt.levels[0][0].addr, 0x200);
        assert_eq!(bt.levels[1].len(), 1);
        assert_eq!(bt.levels[1][0].addr, 0x300);
        assert_eq!(bt.total, 2);
    }

    #[test]
    fn test_trace_stops_early_when_no_more_callers() {
        let edges = three_level_edges();
        // Ask for 10 hops but graph only has 2 levels beyond origin.
        let bt = trace_callers_backward(0x100, 10, &edges);
        assert_eq!(bt.levels.len(), 2, "should stop at graph boundary");
        assert_eq!(bt.total, 2);
    }

    #[test]
    fn test_trace_no_callers_returns_empty() {
        let bt = trace_callers_backward(0xDEAD, 5, &[]);
        assert!(bt.levels.is_empty());
        assert_eq!(bt.total, 0);
    }

    #[test]
    fn test_trace_dedup_multiple_callers_same_node() {
        // Two callers of 0x100, each with a common grandparent.
        let edges: Vec<(u64, u64)> = vec![
            (0x200, 0x100),
            (0x201, 0x100),
            (0x300, 0x200),
            (0x300, 0x201), // same grandparent calls both parents
        ];
        let bt = trace_callers_backward(0x100, 2, &edges);
        assert_eq!(bt.levels[0].len(), 2, "two direct callers");
        assert_eq!(bt.levels[1].len(), 1, "grandparent deduplicated");
        assert_eq!(bt.total, 3);
    }

    // ── new spec'd tests ────────────────────────────────────────────────

    #[test]
    fn test_trace_direct_callers_fanin() {
        // 1 -> 10, 2 -> 10, 3 -> 10
        let edges = [(1u64, 10u64), (2, 10), (3, 10)];
        let bt = trace_callers_backward(10, 1, &edges);
        assert_eq!(bt.levels.len(), 1);
        assert_eq!(bt.total, 3);
        let got: Vec<u64> = bt.levels[0].iter().map(|n| n.addr).collect();
        assert_eq!(got, vec![1, 2, 3]);
        assert!(bt.levels[0].iter().all(|n| n.name.is_none()));
    }

    #[test]
    fn test_trace_cycle_does_not_loop() {
        // Chain: 1 -> 2 -> 3 -> 4 (target). Plus 1 -> 1 self-loop and 2 -> 1
        // back-edge. BFS must not revisit nodes.
        let edges = [(1u64, 2u64), (2, 3), (3, 4), (1, 1), (2, 1)];
        let bt = trace_callers_backward(4, 5, &edges);
        assert_eq!(bt.levels.len(), 3);
        assert_eq!(bt.levels[0].iter().map(|n| n.addr).collect::<Vec<_>>(), vec![3]);
        assert_eq!(bt.levels[1].iter().map(|n| n.addr).collect::<Vec<_>>(), vec![2]);
        assert_eq!(bt.levels[2].iter().map(|n| n.addr).collect::<Vec<_>>(), vec![1]);
        assert_eq!(bt.total, 3);
    }

    #[test]
    fn test_trace_hops_clamped_at_max() {
        // Chain of 20: 0 -> 1 -> 2 -> ... -> 20. Request 1000 hops; must clamp
        // at MAX_BACKWARD_HOPS = 10.
        let chain: Vec<(u64, u64)> = (0..20u64).map(|i| (i, i + 1)).collect();
        let bt = trace_callers_backward(20, 1_000, &chain);
        assert_eq!(bt.levels.len(), MAX_BACKWARD_HOPS);
        assert_eq!(bt.total, MAX_BACKWARD_HOPS);
        // Deepest level reached: node 20 - 10 = 10.
        assert_eq!(
            bt.levels.last().unwrap()[0].addr,
            20 - MAX_BACKWARD_HOPS as u64
        );
    }
}
