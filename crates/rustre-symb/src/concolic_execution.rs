//! `concolic_execution` — Coverage-guided concolic campaign engine.
//!
//! **Layer**: sits above [`concolic`](crate::concolic) (which does the raw
//! flip-and-re-execute loop) and below [`concolic_executor`](crate::concolic_executor)
//! (which wraps a solver).  This module is the coverage-tracking middle layer:
//! it collects already-executed [`SymbolicState`](crate::SymbolicState) paths
//! and decides *which* branch flips to attempt next using a priority queue and
//! deduplication history, rather than driving the actual concrete executions.
//!
//! Provides:
//! * [`ConcolicEngine`] — main driver; iterates over a test-case queue.
//! * [`BranchFlip`] — record of a single branch to be negated.
//! * [`TestCaseQueue`] — priority queue of pending test cases.
//! * [`FlipHistory`] — deduplication set of already-attempted flips.
//! * [`CoverageGuidedFlip`] — score branch flips by new coverage gained.
//! * [`FlipBudget`] — limits on total flips and per-path depth.
//!
//! # Layer overview (within this crate)
//!
//! See [`concolic`](crate::concolic) module docs for the full table.

pub use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

pub use crate::SymType;
use crate::{SymExpr, SymbolicState};

// ─── Coverage ─────────────────────────────────────────────────────────────────

/// A coverage identifier: typically a (basic-block address, successor-address)
/// pair encoded as `from << 32 | to`.
pub type CovEdge = u64;

/// Cumulative coverage set — all edges seen so far.
#[derive(Debug, Clone, Default)]
pub struct Coverage {
    edges: HashSet<CovEdge>,
}

impl Coverage {
    /// Create an empty coverage set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an edge.  Returns `true` if this is a newly seen edge.
    pub fn add(&mut self, edge: CovEdge) -> bool {
        self.edges.insert(edge)
    }

    /// Return `true` if `edge` has been seen.
    #[must_use]
    pub fn contains(&self, edge: CovEdge) -> bool {
        self.edges.contains(&edge)
    }

    /// Return the total number of edges covered.
    #[must_use]
    pub fn count(&self) -> usize {
        self.edges.len()
    }

    /// Return a cloned set of all covered edges.
    #[must_use]
    pub fn all_edges(&self) -> HashSet<CovEdge> {
        self.edges.clone()
    }

    /// Merge `other` into this coverage set.
    pub fn merge(&mut self, other: &Self) {
        self.edges.extend(&other.edges);
    }
}

// ─── BranchFlip ───────────────────────────────────────────────────────────────

/// A record describing one branch in a path condition that should be negated to
/// generate a new test case.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BranchFlip {
    /// Index within the path condition vector.
    pub branch_index: usize,
    /// The branch condition at that index.
    pub condition: SymExpr,
    /// Program counter at which the branch was taken.
    pub pc: u64,
    /// Edge covered by the original direction.
    pub original_edge: CovEdge,
}

impl BranchFlip {
    /// Construct a new `BranchFlip`.
    #[must_use]
    pub const fn new(
        branch_index: usize,
        condition: SymExpr,
        pc: u64,
        original_edge: CovEdge,
    ) -> Self {
        Self {
            branch_index,
            condition,
            pc,
            original_edge,
        }
    }

    /// Negate `condition` to produce the flipped branch constraint.
    #[must_use]
    pub fn flipped_condition(&self) -> SymExpr {
        SymExpr::BoolNot(Box::new(self.condition.clone()))
    }

    /// Derive a new path condition by replacing element `branch_index` with the
    /// negated condition and truncating everything after it.
    #[must_use]
    pub fn apply_to_path(&self, path: &[SymExpr]) -> Vec<SymExpr> {
        let mut new_path = path[..self.branch_index].to_vec();
        new_path.push(self.flipped_condition());
        new_path
    }
}

// ─── TestCase ─────────────────────────────────────────────────────────────────

/// A concrete input assignment that drives one execution path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Mapping from symbolic variable name to concrete value.
    pub input: HashMap<String, u64>,
    /// Priority score (higher = executed sooner).
    pub priority: i64,
    /// Depth of the path that generated this test case.
    pub depth: u32,
    /// The flip that produced this test case (if any).
    pub from_flip: Option<BranchFlip>,
}

impl TestCase {
    /// Construct a seed test case with an explicit input.
    #[must_use]
    pub const fn seed(input: HashMap<String, u64>) -> Self {
        Self {
            input,
            priority: 0,
            depth: 0,
            from_flip: None,
        }
    }

    /// Construct a test case generated from a flip.
    #[must_use]
    pub const fn from_flip(
        input: HashMap<String, u64>,
        depth: u32,
        flip: BranchFlip,
        priority: i64,
    ) -> Self {
        Self {
            input,
            priority,
            depth,
            from_flip: Some(flip),
        }
    }
}

impl PartialEq for TestCase {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for TestCase {}

impl PartialOrd for TestCase {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TestCase {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

// ─── TestCaseQueue ────────────────────────────────────────────────────────────

/// Priority queue of test cases awaiting execution.
///
/// Highest-priority cases are dequeued first.
#[derive(Debug, Default)]
pub struct TestCaseQueue {
    heap: BinaryHeap<TestCase>,
    /// Total test cases ever enqueued.
    total_enqueued: u64,
}

impl TestCaseQueue {
    /// Create a new empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a test case onto the queue.
    pub fn push(&mut self, tc: TestCase) {
        self.total_enqueued += 1;
        self.heap.push(tc);
    }

    /// Pop the highest-priority test case.
    pub fn pop(&mut self) -> Option<TestCase> {
        self.heap.pop()
    }

    /// Peek at the highest-priority test case without removing it.
    #[must_use]
    pub fn peek(&self) -> Option<&TestCase> {
        self.heap.peek()
    }

    /// Return the number of test cases currently in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Return `true` if the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Return the total number of test cases ever enqueued.
    #[must_use]
    pub const fn total_enqueued(&self) -> u64 {
        self.total_enqueued
    }
}

// ─── FlipHistory ─────────────────────────────────────────────────────────────

/// Deduplication set of (pc, `branch_index`) pairs already attempted.
#[derive(Debug, Clone, Default)]
pub struct FlipHistory {
    seen: HashSet<(u64, usize)>,
    /// Total flip attempts recorded.
    total: u64,
}

impl FlipHistory {
    /// Create a new, empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a flip.  Returns `true` if this (pc, index) combination is new.
    pub fn record(&mut self, pc: u64, branch_index: usize) -> bool {
        self.total += 1;
        self.seen.insert((pc, branch_index))
    }

    /// Return `true` if (pc, `branch_index`) has already been attempted.
    #[must_use]
    pub fn already_seen(&self, pc: u64, branch_index: usize) -> bool {
        self.seen.contains(&(pc, branch_index))
    }

    /// Return the total number of flip attempts.
    #[must_use]
    pub const fn total_attempts(&self) -> u64 {
        self.total
    }

    /// Return the number of unique (pc, index) pairs.
    #[must_use]
    pub fn unique_flips(&self) -> usize {
        self.seen.len()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.seen.clear();
        self.total = 0;
    }
}

// ─── CoverageGuidedFlip ───────────────────────────────────────────────────────

/// Scores branch flips based on how many new edges are likely to be covered.
///
/// Flips that target branches near uncovered edges receive a higher score.
#[derive(Debug, Default)]
pub struct CoverageGuidedFlip {
    /// All edges observed across executed paths.
    coverage: Coverage,
    /// Per-edge "heat": how many times each edge was hit.
    edge_heat: HashMap<CovEdge, u64>,
}

impl CoverageGuidedFlip {
    /// Create a new guidance instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a set of edges observed during one execution.
    pub fn record_execution(&mut self, edges: impl IntoIterator<Item = CovEdge>) {
        for edge in edges {
            self.coverage.add(edge);
            *self.edge_heat.entry(edge).or_default() += 1;
        }
    }

    /// Score a branch flip.  Higher score = more promising.
    ///
    /// The heuristic: a flip that has not been seen before scores +100.
    /// For each additional branch in the path that touches a cold (rare) edge,
    /// the score increases by `(max_heat - heat + 1)`.
    #[must_use]
    pub fn score_flip(&self, flip: &BranchFlip, history: &FlipHistory, path_depth: u32) -> i64 {
        let base: i64 = if history.already_seen(flip.pc, flip.branch_index) {
            0
        } else {
            100
        };
        // Penalise deep paths to balance exploration vs. exploitation.
        let depth_penalty = i64::from(path_depth).min(50);
        // Bonus for flipping a "hot" branch — it is more important to diversify.
        let heat = self
            .edge_heat
            .get(&flip.original_edge)
            .copied()
            .unwrap_or(0)
            .cast_signed();
        base - depth_penalty + heat.min(50)
    }

    /// Return total coverage count.
    #[must_use]
    pub fn coverage_count(&self) -> usize {
        self.coverage.count()
    }

    /// Return `true` if `edge` has been covered.
    #[must_use]
    pub fn is_covered(&self, edge: CovEdge) -> bool {
        self.coverage.contains(edge)
    }
}

// ─── FlipBudget ───────────────────────────────────────────────────────────────

/// Hard limits on concolic execution resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlipBudget {
    /// Maximum total number of branch flips across all test cases.
    pub max_total_flips: u64,
    /// Maximum symbolic path depth per test case.
    pub max_depth: u32,
    /// Maximum number of test cases in the queue at any one time.
    pub max_queue_size: usize,
    /// Maximum number of new edges before stopping (coverage saturation).
    pub max_new_edges: usize,
}

impl Default for FlipBudget {
    fn default() -> Self {
        Self {
            max_total_flips: 10_000,
            max_depth: 64,
            max_queue_size: 4096,
            max_new_edges: usize::MAX,
        }
    }
}

impl FlipBudget {
    /// Create a budget with conservative limits for unit tests.
    #[must_use]
    pub const fn for_testing() -> Self {
        Self {
            max_total_flips: 100,
            max_depth: 8,
            max_queue_size: 64,
            max_new_edges: 1000,
        }
    }

    /// Return `true` if `flip_count` has exhausted the total-flip budget.
    #[must_use]
    pub const fn total_exhausted(&self, flip_count: u64) -> bool {
        flip_count >= self.max_total_flips
    }

    /// Return `true` if `depth` exceeds the per-path depth budget.
    #[must_use]
    pub const fn depth_exceeded(&self, depth: u32) -> bool {
        depth > self.max_depth
    }

    /// Return `true` if `queue_size` would exceed the queue-size limit.
    #[must_use]
    pub const fn queue_full(&self, queue_size: usize) -> bool {
        queue_size >= self.max_queue_size
    }
}

// ─── ConcolicEngine ───────────────────────────────────────────────────────────

/// The main concolic execution driver.
///
/// Usage pattern:
/// 1. Push seed inputs via [`Self::push_seed`].
/// 2. Call [`Self::next_test_case`] to dequeue the next input.
/// 3. Run the program concretely with that input, collecting the symbolic
///    path via a [`SymbolicState`].
/// 4. Call [`Self::process_path`] to generate new test cases from the path.
/// 5. Repeat until [`Self::is_done`] returns `true`.
#[derive(Debug)]
pub struct ConcolicEngine {
    queue: TestCaseQueue,
    history: FlipHistory,
    guidance: CoverageGuidedFlip,
    budget: FlipBudget,
    /// Total flips generated so far.
    total_flips: u64,
    /// Total test cases executed.
    executed: u64,
    /// Coverage collected across all runs.
    coverage: Coverage,
}

impl ConcolicEngine {
    /// Create a new engine with default budget.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: TestCaseQueue::new(),
            history: FlipHistory::new(),
            guidance: CoverageGuidedFlip::new(),
            budget: FlipBudget::default(),
            total_flips: 0,
            executed: 0,
            coverage: Coverage::new(),
        }
    }

    /// Create a new engine with a custom budget.
    #[must_use]
    pub fn with_budget(budget: FlipBudget) -> Self {
        Self {
            budget,
            ..Self::new()
        }
    }

    /// Push a seed test case.
    pub fn push_seed(&mut self, input: HashMap<String, u64>) {
        self.queue.push(TestCase::seed(input));
    }

    /// Dequeue the next test case to execute.
    pub fn next_test_case(&mut self) -> Option<TestCase> {
        self.queue.pop()
    }

    /// Process a symbolic state collected after executing `test_case`.
    ///
    /// Generates new test cases by flipping each branch in the path condition,
    /// subject to budget limits and deduplication.
    ///
    /// `new_edges` contains the coverage edges observed during this run.
    pub fn process_path(
        &mut self,
        test_case: &TestCase,
        state: &SymbolicState,
        new_edges: Vec<CovEdge>,
    ) {
        self.executed += 1;
        self.guidance.record_execution(new_edges.iter().copied());
        for edge in new_edges {
            self.coverage.add(edge);
        }

        if self.budget.total_exhausted(self.total_flips) {
            return;
        }

        let path = &state.path_condition;
        let depth = state.depth;

        // Try flipping each branch in the path condition.
        for (i, cond) in path.iter().enumerate() {
            if self.budget.depth_exceeded(depth) {
                break;
            }
            if self.budget.queue_full(self.queue.len()) {
                break;
            }
            if self.budget.total_exhausted(self.total_flips) {
                break;
            }
            // Build a synthetic edge identifier from the PC and branch index.
            let edge = encode_edge(state.pc, u32::try_from(i).unwrap_or(u32::MAX));
            let flip = BranchFlip::new(i, cond.clone(), state.pc, edge);

            if self.history.already_seen(flip.pc, i) {
                continue;
            }

            let score = self.guidance.score_flip(&flip, &self.history, depth);
            self.history.record(flip.pc, i);
            self.total_flips += 1;

            // Build a new path condition with this branch flipped.
            let new_path = flip.apply_to_path(path);

            // Derive concrete inputs from the new path.
            // In a real engine this would call an SMT solver; here we use a
            // simple heuristic: copy the original inputs and mark the flipped
            // variable with a synthetic value.
            let mut new_input = test_case.input.clone();
            synthesise_flip_input(&new_path, &mut new_input);

            let tc = TestCase::from_flip(new_input, depth + 1, flip, score);
            self.queue.push(tc);
        }
    }

    /// Return `true` if the engine has no more work to do.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.queue.is_empty() || self.budget.total_exhausted(self.total_flips)
    }

    /// Return the total number of test cases executed.
    #[must_use]
    pub const fn executed(&self) -> u64 {
        self.executed
    }

    /// Return the total number of branch flips generated.
    #[must_use]
    pub const fn total_flips(&self) -> u64 {
        self.total_flips
    }

    /// Return the current coverage count.
    #[must_use]
    pub fn coverage_count(&self) -> usize {
        self.coverage.count()
    }

    /// Return the number of pending test cases.
    #[must_use]
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Return a reference to the flip history.
    #[must_use]
    pub const fn history(&self) -> &FlipHistory {
        &self.history
    }

    /// Return a reference to the coverage-guided scorer.
    #[must_use]
    pub const fn guidance(&self) -> &CoverageGuidedFlip {
        &self.guidance
    }

    /// Reset the engine, clearing all state.
    pub fn reset(&mut self) {
        self.queue = TestCaseQueue::new();
        self.history.clear();
        self.guidance = CoverageGuidedFlip::new();
        self.total_flips = 0;
        self.executed = 0;
        self.coverage = Coverage::new();
    }
}

impl Default for ConcolicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ConcolicEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConcolicEngine {{ executed={}, flips={}, coverage={}, queue={} }}",
            self.executed,
            self.total_flips,
            self.coverage_count(),
            self.queue_len(),
        )
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn encode_edge(from: u64, step: u32) -> CovEdge {
    (from.wrapping_shr(32) ^ from) ^ u64::from(step).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Heuristic: for each constraint in `path` that involves a `Var`, set that
/// variable to 1 in `input` (a trivial satisfying assignment for `BoolNot`).
fn synthesise_flip_input(path: &[SymExpr], input: &mut HashMap<String, u64>) {
    for expr in path {
        collect_vars_for_input(expr, input);
    }
}

fn collect_vars_for_input(expr: &SymExpr, input: &mut HashMap<String, u64>) {
    match expr {
        SymExpr::Var { name, .. } => {
            input.entry(name.clone()).or_insert(1);
        }
        SymExpr::BoolNot(inner) => {
            // Flipped: toggle known values.
            if let SymExpr::Var { name, .. } = inner.as_ref() {
                let v = input.get(name).copied().unwrap_or(1);
                input.insert(name.clone(), u64::from(v == 0));
            } else {
                collect_vars_for_input(inner, input);
            }
        }
        SymExpr::BoolAnd(l, r)
        | SymExpr::BoolOr(l, r)
        | SymExpr::Eq(l, r)
        | SymExpr::Ne(l, r)
        | SymExpr::ULt(l, r)
        | SymExpr::UGt(l, r)
        | SymExpr::Add(l, r)
        | SymExpr::Sub(l, r)
        | SymExpr::And(l, r)
        | SymExpr::Or(l, r) => {
            collect_vars_for_input(l, input);
            collect_vars_for_input(r, input);
        }
        SymExpr::Not(e)
        | SymExpr::Neg(e)
        | SymExpr::ZExt { expr: e, .. }
        | SymExpr::SExt { expr: e, .. }
        | SymExpr::Extract { expr: e, .. } => {
            collect_vars_for_input(e, input);
        }
        _ => {}
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn var_cond(name: &str) -> SymExpr {
        SymExpr::Var {
            name: name.to_string(),
            ty: SymType::Bool,
        }
    }

    fn _bv(v: u64) -> SymExpr {
        SymExpr::ConstBv { val: v, width: 64 }
    }

    fn seed(inputs: &[(&str, u64)]) -> HashMap<String, u64> {
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    // ── Coverage ─────────────────────────────────────────────────────────

    #[test]
    fn test_coverage_add_new() {
        let mut cov = Coverage::new();
        assert!(cov.add(42));
        assert!(!cov.add(42));
        assert_eq!(cov.count(), 1);
    }

    #[test]
    fn test_coverage_merge() {
        let mut a = Coverage::new();
        a.add(1);
        a.add(2);
        let mut b = Coverage::new();
        b.add(2);
        b.add(3);
        a.merge(&b);
        assert_eq!(a.count(), 3);
    }

    // ── BranchFlip ───────────────────────────────────────────────────────

    #[test]
    fn test_branch_flip_negates_condition() {
        let cond = SymExpr::ConstBool(true);
        let flip = BranchFlip::new(0, cond, 0x1000, 0);
        let flipped = flip.flipped_condition();
        assert!(matches!(flipped, SymExpr::BoolNot(_)));
    }

    #[test]
    fn test_branch_flip_apply_to_path() {
        let path = vec![
            SymExpr::ConstBool(true),
            SymExpr::ConstBool(false),
            SymExpr::ConstBool(true),
        ];
        let flip = BranchFlip::new(1, SymExpr::ConstBool(false), 0x2000, 0);
        let new_path = flip.apply_to_path(&path);
        assert_eq!(new_path.len(), 2); // [0] unchanged, [1] flipped, [2] truncated
        assert_eq!(new_path[0], SymExpr::ConstBool(true));
        assert!(matches!(new_path[1], SymExpr::BoolNot(_)));
    }

    // ── TestCase ─────────────────────────────────────────────────────────

    #[test]
    fn test_test_case_seed() {
        let tc = TestCase::seed(seed(&[("x", 1)]));
        assert_eq!(tc.priority, 0);
        assert!(tc.from_flip.is_none());
    }

    // ── TestCaseQueue ────────────────────────────────────────────────────

    #[test]
    fn test_queue_priority_order() {
        let mut q = TestCaseQueue::new();
        let mut tc1 = TestCase::seed(seed(&[]));
        tc1.priority = 5;
        let mut tc2 = TestCase::seed(seed(&[]));
        tc2.priority = 100;
        q.push(tc1);
        q.push(tc2);
        assert_eq!(q.pop().unwrap().priority, 100);
        assert_eq!(q.pop().unwrap().priority, 5);
    }

    #[test]
    fn test_queue_total_enqueued() {
        let mut q = TestCaseQueue::new();
        for _ in 0..5 {
            q.push(TestCase::seed(seed(&[])));
        }
        assert_eq!(q.total_enqueued(), 5);
        q.pop();
        assert_eq!(q.total_enqueued(), 5); // doesn't decrease on pop
    }

    // ── FlipHistory ──────────────────────────────────────────────────────

    #[test]
    fn test_flip_history_dedup() {
        let mut h = FlipHistory::new();
        assert!(h.record(0x1000, 2));
        assert!(!h.record(0x1000, 2));
        assert!(h.record(0x1000, 3));
        assert_eq!(h.unique_flips(), 2);
    }

    #[test]
    fn test_flip_history_clear() {
        let mut h = FlipHistory::new();
        h.record(0x1000, 0);
        h.clear();
        assert_eq!(h.unique_flips(), 0);
        assert_eq!(h.total_attempts(), 0);
    }

    // ── CoverageGuidedFlip ───────────────────────────────────────────────

    #[test]
    fn test_guided_flip_score_new_flip() {
        let g = CoverageGuidedFlip::new();
        let h = FlipHistory::new();
        let flip = BranchFlip::new(0, SymExpr::ConstBool(true), 0x1000, 99);
        let score = g.score_flip(&flip, &h, 0);
        assert!(score > 0, "new unseen flip should have positive score");
    }

    #[test]
    fn test_guided_flip_score_seen_flip() {
        let g = CoverageGuidedFlip::new();
        let mut h = FlipHistory::new();
        h.record(0x1000, 0);
        let flip = BranchFlip::new(0, SymExpr::ConstBool(true), 0x1000, 99);
        let score = g.score_flip(&flip, &h, 0);
        assert_eq!(score, 0); // seen → base = 0, depth = 0, heat = 0
    }

    #[test]
    fn test_guided_coverage_tracking() {
        let mut g = CoverageGuidedFlip::new();
        g.record_execution([1, 2, 3]);
        assert_eq!(g.coverage_count(), 3);
        assert!(g.is_covered(1));
        assert!(!g.is_covered(99));
    }

    // ── FlipBudget ───────────────────────────────────────────────────────

    #[test]
    fn test_budget_total_exhausted() {
        let b = FlipBudget {
            max_total_flips: 10,
            ..Default::default()
        };
        assert!(!b.total_exhausted(9));
        assert!(b.total_exhausted(10));
    }

    #[test]
    fn test_budget_depth_exceeded() {
        let b = FlipBudget {
            max_depth: 16,
            ..Default::default()
        };
        assert!(!b.depth_exceeded(16));
        assert!(b.depth_exceeded(17));
    }

    #[test]
    fn test_budget_queue_full() {
        let b = FlipBudget {
            max_queue_size: 5,
            ..Default::default()
        };
        assert!(b.queue_full(5));
        assert!(!b.queue_full(4));
    }

    // ── ConcolicEngine ───────────────────────────────────────────────────

    #[test]
    fn test_engine_push_and_pop_seed() {
        let mut engine = ConcolicEngine::new();
        engine.push_seed(seed(&[("x", 42)]));
        let tc = engine.next_test_case().unwrap();
        assert_eq!(tc.input["x"], 42);
    }

    #[test]
    fn test_engine_is_done_when_empty() {
        let engine = ConcolicEngine::new();
        assert!(engine.is_done());
    }

    #[test]
    fn test_engine_process_path_generates_flips() {
        let mut engine = ConcolicEngine::with_budget(FlipBudget::for_testing());
        engine.push_seed(seed(&[("a", 1)]));
        let tc = engine.next_test_case().unwrap();

        // Simulate a symbolic state with one branch in the path condition.
        let mut state = SymbolicState::new();
        state.pc = 0x4000;
        state.path_condition.push(var_cond("a"));

        engine.process_path(&tc, &state, vec![encode_edge(0x4000, 0)]);
        assert_eq!(engine.total_flips(), 1);
        assert_eq!(engine.queue_len(), 1);
    }

    #[test]
    fn test_engine_no_duplicate_flips() {
        let mut engine = ConcolicEngine::with_budget(FlipBudget::for_testing());
        engine.push_seed(seed(&[("a", 1)]));

        // Execute twice with the same path condition.
        let mut state = SymbolicState::new();
        state.pc = 0x4000;
        state.path_condition.push(var_cond("a"));

        let tc1 = TestCase::seed(seed(&[("a", 1)]));
        engine.process_path(&tc1, &state, vec![]);
        let flips_after_1 = engine.total_flips();

        let tc2 = TestCase::seed(seed(&[("a", 1)]));
        engine.process_path(&tc2, &state, vec![]);
        // Should not generate a duplicate.
        assert_eq!(engine.total_flips(), flips_after_1);
    }

    #[test]
    fn test_engine_budget_limits_flips() {
        let budget = FlipBudget {
            max_total_flips: 3,
            max_depth: 100,
            max_queue_size: 1000,
            max_new_edges: 1000,
        };
        let mut engine = ConcolicEngine::with_budget(budget);
        let mut state = SymbolicState::new();
        state.pc = 0x1000;
        for i in 0..10u64 {
            state.path_condition.push(SymExpr::Var {
                name: format!("c{i}"),
                ty: SymType::Bool,
            });
        }
        let tc = TestCase::seed(seed(&[]));
        engine.process_path(&tc, &state, vec![]);
        assert!(engine.total_flips() <= 3);
    }

    #[test]
    fn test_engine_reset() {
        let mut engine = ConcolicEngine::new();
        engine.push_seed(seed(&[("x", 1)]));
        engine.reset();
        assert!(engine.is_done());
        assert_eq!(engine.executed(), 0);
        assert_eq!(engine.total_flips(), 0);
    }

    #[test]
    fn test_engine_coverage_accumulates() {
        let mut engine = ConcolicEngine::new();
        let tc = TestCase::seed(seed(&[]));
        let state = SymbolicState::new();
        engine.process_path(&tc, &state, vec![1, 2, 3]);
        engine.process_path(&tc, &state, vec![3, 4, 5]);
        assert_eq!(engine.coverage_count(), 5); // {1,2,3,4,5}
    }

    #[test]
    fn test_engine_display() {
        let engine = ConcolicEngine::new();
        let s = engine.to_string();
        assert!(s.contains("ConcolicEngine"));
    }

    #[test]
    fn test_branch_flip_new_fields() {
        let flip = BranchFlip::new(3, SymExpr::ConstBool(false), 0xDEAD, 0xBEEF);
        assert_eq!(flip.branch_index, 3);
        assert_eq!(flip.pc, 0xDEAD);
        assert_eq!(flip.original_edge, 0xBEEF);
    }

    #[test]
    fn test_synthesise_flip_input_toggles_var() {
        let path = vec![SymExpr::BoolNot(Box::new(SymExpr::Var {
            name: "flag".to_string(),
            ty: SymType::Bool,
        }))];
        let mut input = HashMap::new();
        input.insert("flag".to_string(), 1u64);
        synthesise_flip_input(&path, &mut input);
        assert_eq!(input["flag"], 0); // toggled
    }
}
