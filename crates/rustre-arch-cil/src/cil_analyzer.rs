//! CIL / MSIL bytecode analysis — stack depth, exception flow,
//! call graphs, type usage, and complexity metrics.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CilAnalysisError {
    #[error("invalid opcode 0x{0:04x} at offset {1}")]
    InvalidOpcode(u16, usize),
    #[error("stack underflow at offset {0}")]
    StackUnderflow(usize),
    #[error("stack overflow at offset {0} (depth {1})")]
    StackOverflow(usize, usize),
    #[error("invalid method token 0x{0:08x}")]
    InvalidToken(u32),
    #[error("cycle detected in call graph")]
    CallGraphCycle,
    #[error("missing handler for try block at offset {0}")]
    MissingHandler(usize),
}

// ─── Tokens and References ────────────────────────────────────────────────────

/// A CIL metadata token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MetadataToken(pub u32);

impl MetadataToken {
    #[must_use]
    pub const fn table(&self) -> u8 {
        (self.0 >> 24) as u8
    }
    #[must_use]
    pub const fn rid(&self) -> u32 {
        self.0 & 0x00FF_FFFF
    }
    #[must_use]
    pub const fn is_method_def(&self) -> bool {
        self.table() == 0x06
    }
    #[must_use]
    pub const fn is_type_ref(&self) -> bool {
        self.table() == 0x01
    }
    #[must_use]
    pub const fn is_member_ref(&self) -> bool {
        self.table() == 0x0A
    }
}

impl std::fmt::Display for MetadataToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}

// ─── Stack Depth Analysis ─────────────────────────────────────────────────────

/// Represents the abstract stack state at a CIL IL offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackState {
    pub offset: usize,
    pub depth: i32,
    pub is_exception_handler_entry: bool,
}

/// Result of CIL stack-depth analysis over a method body.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StackDepthAnalysis {
    /// Stack depth at every reachable IL offset.
    pub depth_map: BTreeMap<usize, i32>,
    /// Maximum observed stack depth.
    pub max_depth: i32,
    /// IL offsets at which the stack was empty (candidate return points).
    pub empty_offsets: Vec<usize>,
    /// Detected stack imbalances: (offset, expected, actual).
    pub imbalances: Vec<(usize, i32, i32)>,
}

impl StackDepthAnalysis {
    /// Run analysis on a sequence of `(il_offset, delta)` pairs.
    ///
    /// `delta` is the net stack change for the instruction at that offset.
    /// # Errors
    ///
    /// Returns [`CilAnalysisError::StackUnderflow`] if the running depth would
    /// go negative, and [`CilAnalysisError::StackOverflow`] if it exceeds the
    /// 1024-slot evaluation-stack limit.
    pub fn analyze(instructions: &[(usize, i32)]) -> Result<Self, CilAnalysisError> {
        let mut result = Self::default();
        let mut depth: i32 = 0;

        for &(offset, delta) in instructions {
            if let Some(&prev) = result.depth_map.get(&offset)
                && prev != depth {
                    result.imbalances.push((offset, prev, depth));
                }
            depth += delta;
            if depth < 0 {
                return Err(CilAnalysisError::StackUnderflow(offset));
            }
            if depth > 1024 {
                // `depth` is > 1024 here and was proven non-negative just above,
                // so the widening to `usize` is exact.
                return Err(CilAnalysisError::StackOverflow(
                    offset,
                    usize::try_from(depth).unwrap_or(usize::MAX),
                ));
            }
            result.depth_map.insert(offset, depth);
            result.max_depth = result.max_depth.max(depth);
            if depth == 0 {
                result.empty_offsets.push(offset);
            }
        }
        Ok(result)
    }

    /// Check if the stack is balanced at all exit points.
    #[must_use]
    pub const fn is_balanced(&self) -> bool {
        self.imbalances.is_empty()
    }
}

// ─── Exception Flow Analysis ──────────────────────────────────────────────────

/// CIL exception handling clause kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClauseKind {
    /// `catch` clause: handles exception of a specific type.
    Catch(MetadataToken),
    /// `filter` clause: boolean-expression filter.
    Filter { filter_offset: usize },
    /// `finally` clause: always executed.
    Finally,
    /// `fault` clause: executed only on exception.
    Fault,
}

/// One `try`/`catch`/`finally`/`filter`/`fault` clause.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionClause {
    pub kind: ClauseKind,
    pub try_start: usize,
    pub try_end: usize,
    pub handler_start: usize,
    pub handler_end: usize,
}

impl ExceptionClause {
    /// Whether a given IL offset falls within the try block.
    #[must_use]
    pub const fn contains_try(&self, offset: usize) -> bool {
        offset >= self.try_start && offset < self.try_end
    }

    /// Whether a given IL offset falls within the handler block.
    #[must_use]
    pub const fn contains_handler(&self, offset: usize) -> bool {
        offset >= self.handler_start && offset < self.handler_end
    }
}

/// Result of exception-flow analysis over a method.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ExceptionFlowAnalysis {
    pub clauses: Vec<ExceptionClause>,
    /// For each try-start offset: list of associated handler offsets.
    pub try_to_handlers: HashMap<usize, Vec<usize>>,
    /// Protected region nesting depth at each offset.
    pub nesting_depth: BTreeMap<usize, usize>,
}

impl ExceptionFlowAnalysis {
    /// Build exception flow analysis from a list of clauses.
    #[must_use]
    pub fn build(clauses: Vec<ExceptionClause>) -> Self {
        // Maximum number of IL offsets we will track for nesting depth.
        // Prevents DoS: an attacker-supplied clause with try_start=0, try_end=usize::MAX
        // would otherwise iterate billions of times.
        const MAX_NESTING_OFFSETS: usize = 1 << 20; // 1 M offsets ≈ realistic method body limit

        let mut try_to_handlers: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut nesting: BTreeMap<usize, usize> = BTreeMap::new();
        for c in &clauses {
            try_to_handlers
                .entry(c.try_start)
                .or_default()
                .push(c.handler_start);
            // Guard against absurdly large try regions from untrusted input.
            let range_len = c.try_end.saturating_sub(c.try_start);
            if range_len <= MAX_NESTING_OFFSETS {
                for off in c.try_start..c.try_end {
                    *nesting.entry(off).or_insert(0) += 1;
                }
            }
        }
        Self {
            clauses,
            try_to_handlers,
            nesting_depth: nesting,
        }
    }

    /// Maximum nesting depth of try regions.
    #[must_use]
    pub fn max_nesting(&self) -> usize {
        self.nesting_depth.values().copied().max().unwrap_or(0)
    }

    /// Offsets that are entry points of exception handlers.
    #[must_use]
    pub fn handler_entries(&self) -> Vec<usize> {
        self.clauses.iter().map(|c| c.handler_start).collect()
    }

    /// Number of `finally` clauses.
    #[must_use]
    pub fn finally_count(&self) -> usize {
        self.clauses
            .iter()
            .filter(|c| c.kind == ClauseKind::Finally)
            .count()
    }
}

// ─── Method Call Graph ────────────────────────────────────────────────────────

/// A node in the CIL method call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    pub token: MetadataToken,
    pub name: String,
    pub callees: Vec<MetadataToken>,
    pub callers: Vec<MetadataToken>,
    pub call_count: usize,
}

impl CallGraphNode {
    /// Create a new node.
    #[must_use]
    pub fn new(token: MetadataToken, name: impl Into<String>) -> Self {
        Self {
            token,
            name: name.into(),
            callees: Vec::new(),
            callers: Vec::new(),
            call_count: 0,
        }
    }
}

/// CIL inter-procedural method call graph.
#[derive(Debug, Default)]
pub struct MethodCallGraph {
    nodes: HashMap<MetadataToken, CallGraphNode>,
}

impl MethodCallGraph {
    /// Insert a new method node.
    pub fn add_method(&mut self, token: MetadataToken, name: impl Into<String>) {
        self.nodes
            .entry(token)
            .or_insert_with(|| CallGraphNode::new(token, name));
    }

    /// Record a call edge from `caller` to `callee`.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: both nodes are inserted immediately before
    /// they are looked up, so the lookups always succeed.
    pub fn add_call(&mut self, from_token: MetadataToken, to_token: MetadataToken) {
        self.nodes
            .entry(from_token)
            .or_insert_with(|| CallGraphNode::new(from_token, "?"));
        self.nodes
            .entry(to_token)
            .or_insert_with(|| CallGraphNode::new(to_token, "?"));
        {
            let c = self.nodes.get_mut(&from_token).unwrap();
            if !c.callees.contains(&to_token) {
                c.callees.push(to_token);
            }
            c.call_count += 1;
        }
        {
            let c = self.nodes.get_mut(&to_token).unwrap();
            if !c.callers.contains(&from_token) {
                c.callers.push(from_token);
            }
        }
    }

    /// BFS reachability: all callees reachable from `root`.
    #[must_use]
    pub fn reachable_from(&self, root: MetadataToken) -> HashSet<MetadataToken> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(root);
        while let Some(tok) = queue.pop_front() {
            if !visited.insert(tok) {
                continue;
            }
            if let Some(node) = self.nodes.get(&tok) {
                for &callee in &node.callees {
                    queue.push_back(callee);
                }
            }
        }
        visited
    }

    /// Detect cycles using DFS. Returns `true` if a cycle exists.
    #[must_use]
    pub fn has_cycle(&self) -> bool {
        let mut visited = HashSet::new();
        let mut stack_set = HashSet::new();
        for &start in self.nodes.keys() {
            if self.dfs_cycle(start, &mut visited, &mut stack_set) {
                return true;
            }
        }
        false
    }

    fn dfs_cycle(
        &self,
        node: MetadataToken,
        visited: &mut HashSet<MetadataToken>,
        stack: &mut HashSet<MetadataToken>,
    ) -> bool {
        if stack.contains(&node) {
            return true;
        }
        if visited.contains(&node) {
            return false;
        }
        visited.insert(node);
        stack.insert(node);
        if let Some(n) = self.nodes.get(&node) {
            for &callee in &n.callees {
                if self.dfs_cycle(callee, visited, stack) {
                    return true;
                }
            }
        }
        stack.remove(&node);
        false
    }

    /// All nodes (methods).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// All edge count (call sites).
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.nodes.values().map(|n| n.callees.len()).sum()
    }

    /// Root methods — those with no callers within the graph.
    #[must_use]
    pub fn roots(&self) -> Vec<MetadataToken> {
        self.nodes
            .values()
            .filter(|n| n.callers.is_empty())
            .map(|n| n.token)
            .collect()
    }

    /// Leaf methods — those with no callees.
    #[must_use]
    pub fn leaves(&self) -> Vec<MetadataToken> {
        self.nodes
            .values()
            .filter(|n| n.callees.is_empty())
            .map(|n| n.token)
            .collect()
    }
}

// ─── TypeUsageMap ─────────────────────────────────────────────────────────────

/// Tracks how types are used within a CIL method body.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TypeUsageMap {
    /// Token → list of IL offsets where the type is referenced.
    pub usages: HashMap<MetadataToken, Vec<usize>>,
    /// Tokens used more than once (potential hot types).
    pub frequent: Vec<MetadataToken>,
}

impl TypeUsageMap {
    /// Record a type usage at a given IL offset.
    pub fn record(&mut self, token: MetadataToken, offset: usize) {
        self.usages.entry(token).or_default().push(offset);
    }

    /// Finalize: compute frequent tokens (used > `threshold` times).
    pub fn finalize(&mut self, threshold: usize) {
        self.frequent = self
            .usages
            .iter()
            .filter(|(_, offsets)| offsets.len() > threshold)
            .map(|(&tok, _)| tok)
            .collect();
    }

    /// Number of distinct types referenced.
    #[must_use]
    pub fn distinct_type_count(&self) -> usize {
        self.usages.len()
    }

    /// All IL offsets where `token` is used.
    #[must_use]
    pub fn offsets_for(&self, token: MetadataToken) -> &[usize] {
        self.usages.get(&token).map_or(&[], std::vec::Vec::as_slice)
    }
}

// ─── CilComplexity ────────────────────────────────────────────────────────────

/// Cyclomatic complexity metrics for a CIL method.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CilComplexity {
    /// Number of basic blocks.
    pub basic_block_count: usize,
    /// Number of branches (conditional + unconditional).
    pub branch_count: usize,
    /// `McCabe` cyclomatic complexity: E - N + 2P.
    pub cyclomatic: usize,
    /// Number of IL instructions.
    pub instruction_count: usize,
    /// Maximum basic block size in instructions.
    pub max_bb_size: usize,
    /// Number of exception clauses.
    pub exception_clause_count: usize,
}

impl CilComplexity {
    /// Compute from basic-block-level data.
    #[must_use]
    pub const fn compute(
        basic_block_count: usize,
        branch_count: usize,
        instruction_count: usize,
        max_bb_size: usize,
        exception_clause_count: usize,
    ) -> Self {
        let edges = branch_count + basic_block_count.saturating_sub(1);
        let cyclomatic = if basic_block_count == 0 {
            1
        } else {
            edges.saturating_sub(basic_block_count) + 2
        };
        Self {
            basic_block_count,
            branch_count,
            cyclomatic,
            instruction_count,
            max_bb_size,
            exception_clause_count,
        }
    }

    /// Whether this method is considered complex (cyclomatic > 10).
    #[must_use]
    pub const fn is_complex(&self) -> bool {
        self.cyclomatic > 10
    }

    /// Estimated risk level based on cyclomatic complexity.
    #[must_use]
    pub const fn risk_label(&self) -> &'static str {
        match self.cyclomatic {
            0..=4 => "low",
            5..=10 => "moderate",
            11..=20 => "high",
            _ => "very_high",
        }
    }
}

// ─── CilAnalyzer ──────────────────────────────────────────────────────────────

/// Top-level CIL method analyzer.
#[derive(Debug, Default)]
pub struct CilAnalyzer {
    pub stack: StackDepthAnalysis,
    pub exc_flow: ExceptionFlowAnalysis,
    pub call_graph: MethodCallGraph,
    pub type_usage: TypeUsageMap,
    pub complexity: CilComplexity,
}

/// Basic-block statistics for one method body.
///
/// Grouped into a struct so [`CilAnalyzer::analyze`] takes one meaningful
/// parameter instead of three bare `usize`s that are easy to transpose.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BasicBlockStats {
    /// Number of basic blocks in the method body.
    pub bb_count: usize,
    /// Number of branch instructions in the method body.
    pub branch_count: usize,
    /// Size, in instructions, of the largest basic block.
    pub max_bb_size: usize,
}

impl CilAnalyzer {
    /// Create a new, empty analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all sub-analyses given raw method data.
    ///
    /// * `stack_deltas` — `(il_offset, delta)` pairs
    /// * `clauses`      — exception clauses
    /// * `calls`        — `(caller_token, callee_token)` pairs
    /// * `type_refs`    — `(type_token, il_offset)` pairs
    /// * `bb_stats`     — basic block statistics for the method body
    ///
    /// # Errors
    ///
    /// Propagates [`CilAnalysisError`] from the stack-depth sub-analysis.
    pub fn analyze(
        &mut self,
        method_token: MetadataToken,
        stack_deltas: &[(usize, i32)],
        clauses: Vec<ExceptionClause>,
        calls: &[(MetadataToken, MetadataToken)],
        type_refs: &[(MetadataToken, usize)],
        bb_stats: BasicBlockStats,
    ) -> Result<(), CilAnalysisError> {
        self.stack = StackDepthAnalysis::analyze(stack_deltas)?;
        self.exc_flow = ExceptionFlowAnalysis::build(clauses);
        self.call_graph
            .add_method(method_token, format!("{method_token}"));
        for &(caller, callee) in calls {
            self.call_graph.add_call(caller, callee);
        }
        for &(tok, off) in type_refs {
            self.type_usage.record(tok, off);
        }
        self.type_usage.finalize(1);
        self.complexity = CilComplexity::compute(
            bb_stats.bb_count,
            bb_stats.branch_count,
            stack_deltas.len(),
            bb_stats.max_bb_size,
            self.exc_flow.clauses.len(),
        );
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(v: u32) -> MetadataToken {
        MetadataToken(v)
    }

    // ── MetadataToken ───────────────────────────────────────────────────────

    #[test]
    fn test_token_table_extraction() {
        let t = tok(0x06_00_00_01);
        assert_eq!(t.table(), 0x06);
        assert!(t.is_method_def());
    }

    #[test]
    fn test_token_rid() {
        let t = tok(0x01_AB_CD_EF);
        assert_eq!(t.rid(), 0xAB_CD_EF);
    }

    #[test]
    fn test_token_type_ref() {
        let t = tok(0x01_00_00_05);
        assert!(t.is_type_ref());
    }

    // ── StackDepthAnalysis ──────────────────────────────────────────────────

    #[test]
    fn test_stack_basic_push_pop() {
        let ops = vec![(0, 1), (4, 1), (8, -1), (12, -1)];
        let r = StackDepthAnalysis::analyze(&ops).unwrap();
        assert_eq!(r.max_depth, 2);
        assert!(r.empty_offsets.contains(&12));
    }

    #[test]
    fn test_stack_underflow_error() {
        let ops = vec![(0, 1), (4, -2)]; // pops 2 from depth 1
        let r = StackDepthAnalysis::analyze(&ops);
        assert!(matches!(r, Err(CilAnalysisError::StackUnderflow(_))));
    }

    #[test]
    fn test_stack_balanced() {
        let ops = vec![(0, 1), (4, -1)];
        let r = StackDepthAnalysis::analyze(&ops).unwrap();
        assert!(r.is_balanced());
    }

    #[test]
    fn test_stack_empty_offsets() {
        let ops = vec![(0, 0), (4, 1), (8, -1)];
        let r = StackDepthAnalysis::analyze(&ops).unwrap();
        assert!(r.empty_offsets.contains(&8) || r.empty_offsets.contains(&0));
    }

    #[test]
    fn test_stack_max_depth() {
        let ops = vec![(0, 1), (4, 1), (8, 1), (12, -1), (16, -1), (20, -1)];
        let r = StackDepthAnalysis::analyze(&ops).unwrap();
        assert_eq!(r.max_depth, 3);
    }

    // ── ExceptionFlowAnalysis ───────────────────────────────────────────────

    fn make_clause(ts: usize, te: usize, hs: usize, he: usize) -> ExceptionClause {
        ExceptionClause {
            kind: ClauseKind::Finally,
            try_start: ts,
            try_end: te,
            handler_start: hs,
            handler_end: he,
        }
    }

    #[test]
    fn test_exception_flow_empty() {
        let efa = ExceptionFlowAnalysis::build(vec![]);
        assert_eq!(efa.max_nesting(), 0);
    }

    #[test]
    fn test_exception_flow_nesting() {
        let outer = make_clause(0, 20, 20, 30);
        let inner = make_clause(5, 15, 30, 40);
        let efa = ExceptionFlowAnalysis::build(vec![outer, inner]);
        assert_eq!(efa.max_nesting(), 2);
    }

    #[test]
    fn test_exception_handler_entries() {
        let c = make_clause(0, 10, 10, 20);
        let efa = ExceptionFlowAnalysis::build(vec![c]);
        assert_eq!(efa.handler_entries(), vec![10]);
    }

    #[test]
    fn test_exception_finally_count() {
        let c1 = make_clause(0, 10, 10, 20);
        let c2 = ExceptionClause {
            kind: ClauseKind::Catch(tok(0x0100_0001)),
            try_start: 0,
            try_end: 10,
            handler_start: 20,
            handler_end: 30,
        };
        let efa = ExceptionFlowAnalysis::build(vec![c1, c2]);
        assert_eq!(efa.finally_count(), 1);
    }

    #[test]
    fn test_clause_contains_try() {
        let c = make_clause(10, 20, 20, 30);
        assert!(c.contains_try(15));
        assert!(!c.contains_try(5));
        assert!(!c.contains_try(20));
    }

    #[test]
    fn test_clause_contains_handler() {
        let c = make_clause(0, 10, 10, 20);
        assert!(c.contains_handler(15));
        assert!(!c.contains_handler(5));
    }

    // ── MethodCallGraph ─────────────────────────────────────────────────────

    #[test]
    fn test_call_graph_add_edge() {
        let mut g = MethodCallGraph::default();
        g.add_method(tok(1), "A");
        g.add_method(tok(2), "B");
        g.add_call(tok(1), tok(2));
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn test_call_graph_roots_leaves() {
        let mut g = MethodCallGraph::default();
        g.add_method(tok(1), "root");
        g.add_method(tok(2), "leaf");
        g.add_call(tok(1), tok(2));
        let roots = g.roots();
        let leaves = g.leaves();
        assert!(roots.contains(&tok(1)));
        assert!(leaves.contains(&tok(2)));
    }

    #[test]
    fn test_call_graph_reachable() {
        let mut g = MethodCallGraph::default();
        g.add_call(tok(1), tok(2));
        g.add_call(tok(2), tok(3));
        let r = g.reachable_from(tok(1));
        assert!(r.contains(&tok(1)));
        assert!(r.contains(&tok(2)));
        assert!(r.contains(&tok(3)));
    }

    #[test]
    fn test_call_graph_no_cycle_by_default() {
        let mut g = MethodCallGraph::default();
        g.add_call(tok(1), tok(2));
        g.add_call(tok(2), tok(3));
        assert!(!g.has_cycle());
    }

    #[test]
    fn test_call_graph_cycle_detected() {
        let mut g = MethodCallGraph::default();
        g.add_call(tok(1), tok(2));
        g.add_call(tok(2), tok(3));
        g.add_call(tok(3), tok(1));
        assert!(g.has_cycle());
    }

    // ── TypeUsageMap ────────────────────────────────────────────────────────

    #[test]
    fn test_type_usage_record_and_count() {
        let mut m = TypeUsageMap::default();
        m.record(tok(1), 0);
        m.record(tok(1), 4);
        m.record(tok(2), 8);
        assert_eq!(m.distinct_type_count(), 2);
        assert_eq!(m.offsets_for(tok(1)).len(), 2);
    }

    #[test]
    fn test_type_usage_frequent() {
        let mut m = TypeUsageMap::default();
        for i in 0..5 {
            m.record(tok(1), i);
        }
        m.record(tok(2), 0);
        m.finalize(2);
        assert!(m.frequent.contains(&tok(1)));
        assert!(!m.frequent.contains(&tok(2)));
    }

    // ── CilComplexity ───────────────────────────────────────────────────────

    #[test]
    fn test_complexity_low() {
        let c = CilComplexity::compute(2, 1, 10, 5, 0);
        assert_eq!(c.risk_label(), "low");
    }

    #[test]
    fn test_complexity_high() {
        let c = CilComplexity::compute(20, 18, 100, 10, 2);
        assert!(c.cyclomatic > 10);
        assert!(c.is_complex());
    }

    #[test]
    fn test_complexity_empty_method() {
        let c = CilComplexity::compute(0, 0, 0, 0, 0);
        assert_eq!(c.cyclomatic, 1);
    }

    // ── CilAnalyzer ─────────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_full_run() {
        let mut a = CilAnalyzer::new();
        let stack_deltas = vec![(0, 1), (4, 1), (8, -1), (12, -1)];
        let clause = ExceptionClause {
            kind: ClauseKind::Finally,
            try_start: 0,
            try_end: 8,
            handler_start: 8,
            handler_end: 12,
        };
        let calls = vec![(tok(1), tok(2))];
        let type_refs = vec![(tok(0x0100_0001), 4)];
        a.analyze(
            tok(1),
            &stack_deltas,
            vec![clause],
            &calls,
            &type_refs,
            BasicBlockStats { bb_count: 3, branch_count: 2, max_bb_size: 4 },
        )
        .unwrap();
        assert_eq!(a.stack.max_depth, 2);
        assert_eq!(a.exc_flow.finally_count(), 1);
        assert_eq!(a.call_graph.edge_count(), 1);
        assert_eq!(a.type_usage.distinct_type_count(), 1);
    }

    #[test]
    fn test_analyzer_underflow_propagates() {
        let mut a = CilAnalyzer::new();
        let r = a.analyze(
            tok(1),
            &[(0, 1), (4, -2)],
            vec![],
            &[],
            &[],
            BasicBlockStats { bb_count: 1, branch_count: 0, max_bb_size: 1 },
        );
        assert!(r.is_err());
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_stack_depth_map_has_entry() {
        let ops = vec![(0, 1), (4, -1)];
        let r = StackDepthAnalysis::analyze(&ops).unwrap();
        assert!(r.depth_map.contains_key(&0));
    }

    #[test]
    fn test_complexity_risk_moderate() {
        let c = CilComplexity::compute(6, 5, 30, 5, 0);
        assert_eq!(c.risk_label(), "moderate");
    }

    #[test]
    fn test_complexity_not_complex_low() {
        let c = CilComplexity::compute(2, 1, 5, 3, 0);
        assert!(!c.is_complex());
    }

    #[test]
    fn test_type_usage_empty_frequent() {
        let mut m = TypeUsageMap::default();
        m.record(tok(1), 0);
        m.finalize(5); // threshold 5, only 1 usage
        assert!(m.frequent.is_empty());
    }

    #[test]
    fn test_call_graph_multiple_callers() {
        let mut g = MethodCallGraph::default();
        g.add_call(tok(1), tok(3));
        g.add_call(tok(2), tok(3));
        let node = g.nodes.get(&tok(3)).unwrap();
        assert_eq!(node.callers.len(), 2);
    }

    #[test]
    fn test_exception_clause_filter() {
        let catch = ExceptionClause {
            kind: ClauseKind::Catch(tok(0x0100_0001)),
            try_start: 0,
            try_end: 10,
            handler_start: 10,
            handler_end: 20,
        };
        let efa = ExceptionFlowAnalysis::build(vec![catch]);
        assert_eq!(efa.finally_count(), 0);
    }
}
