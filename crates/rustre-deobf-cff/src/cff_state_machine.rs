//! Control-flow flattening state machine detector and analyser.
//!
//! Detects dispatcher blocks, extracts the state variable, builds the state
//! transition graph, and topologically sorts the state sequence to recover
//! the original control flow.

use std::collections::{HashMap, HashSet, VecDeque};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmError {
    NoDispatcherFound,
    AmbiguousDispatcher,
    StateVarUnresolved,
    CyclicDependency,
    EmptyCfg,
    InvalidBlock(u64),
}

impl std::fmt::Display for SmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDispatcherFound => write!(f, "no CFF dispatcher found"),
            Self::AmbiguousDispatcher => write!(f, "multiple plausible dispatchers"),
            Self::StateVarUnresolved => write!(f, "cannot resolve state variable"),
            Self::CyclicDependency => write!(f, "cyclic dependency in state order"),
            Self::EmptyCfg => write!(f, "empty CFG"),
            Self::InvalidBlock(a) => write!(f, "invalid block address: 0x{a:x}"),
        }
    }
}

impl std::error::Error for SmError {}

// ─── StateMachinePattern ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateMachinePattern {
    SwitchDispatcher,
    WhileTrue,
    DoWhile,
    ForLoop,
    GotoDispatcher,
}

// ─── DispatcherInfo ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DispatcherInfo {
    pub dispatcher_addr: u64,
    pub state_var_offset: Option<i32>,
    pub dispatch_block_addrs: Vec<u64>,
    pub num_states: usize,
    pub pattern: StateMachinePattern,
}

// ─── StateBlock ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StateBlock {
    pub state_id: u32,
    pub block_addr: u64,
    pub next_states: Vec<u32>,
    pub is_terminal: bool,
    pub real_successor: Option<u64>,
    pub instructions: Vec<String>,
}

// ─── CffReport ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CffReport {
    pub is_flattened: bool,
    pub dispatcher_count: u32,
    pub state_count: u32,
    pub complexity_reduction: f64,
}

// ─── BasicBlock (input model) ─────────────────────────────────────────────────

/// Minimal basic block description used as input to the analyser.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub addr: u64,
    pub successors: Vec<u64>,
    pub instructions: Vec<String>,
    /// The loop depth of this block (0 = function entry level).
    pub loop_depth: u32,
    /// If the block ends with a switch/indirect jump, the case targets.
    pub switch_targets: Vec<u64>,
    /// Register/stack slot that is read to dispatch (if known).
    pub dispatch_read: Option<DispatchRead>,
}

#[derive(Debug, Clone)]
pub struct DispatchRead {
    pub stack_offset: Option<i32>,
    pub register: Option<String>,
}

impl BasicBlock {
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self {
            addr,
            successors: Vec::new(),
            instructions: Vec::new(),
            loop_depth: 0,
            switch_targets: Vec::new(),
            dispatch_read: None,
        }
    }
}

// ─── CffStateMachine ─────────────────────────────────────────────────────────

pub struct CffStateMachine {
    blocks: HashMap<u64, BasicBlock>,
    min_switch_cases: usize,
}

impl CffStateMachine {
    #[must_use]
    pub fn new() -> Self {
        Self { blocks: HashMap::new(), min_switch_cases: 5 }
    }

    #[must_use]
    pub const fn with_min_cases(mut self, n: usize) -> Self {
        self.min_switch_cases = n;
        self
    }

    /// Add a basic block to the CFG.
    pub fn add_block(&mut self, block: BasicBlock) {
        self.blocks.insert(block.addr, block);
    }

    /// Detect the dispatcher block(s). A dispatcher has:
    /// - a large switch (>= `min_switch_cases` successors),
    /// - all successors at the same loop depth,
    /// - a single variable read determining the branch.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the CFG is empty or no dispatcher block is found.
    pub fn detect_dispatcher(&self) -> Result<DispatcherInfo, SmError> {
        if self.blocks.is_empty() {
            return Err(SmError::EmptyCfg);
        }

        let mut candidates: Vec<&BasicBlock> = self
            .blocks
            .values()
            .filter(|b| b.switch_targets.len() >= self.min_switch_cases)
            .collect();

        if candidates.is_empty() {
            // Fall back: look for blocks with many successors
            candidates = self
                .blocks
                .values()
                .filter(|b| b.successors.len() >= self.min_switch_cases)
                .collect();
        }

        if candidates.is_empty() {
            return Err(SmError::NoDispatcherFound);
        }

        // Score: prefer block with the most targets whose successors share loop depth
        candidates.sort_by_key(|b| {
            let targets = if b.switch_targets.is_empty() { &b.successors } else { &b.switch_targets };
            let dispatcher_depth = b.loop_depth;
            let same_depth = targets
                .iter()
                .filter(|&&addr| {
                    self.blocks.get(&addr).is_some_and(|b2| b2.loop_depth == dispatcher_depth)
                })
                .count();
            std::cmp::Reverse(same_depth)
        });

        let best = candidates[0];
        let targets = if best.switch_targets.is_empty() {
            best.successors.clone()
        } else {
            best.switch_targets.clone()
        };

        let state_var_offset = best.dispatch_read.as_ref().and_then(|dr| dr.stack_offset);

        Ok(DispatcherInfo {
            dispatcher_addr: best.addr,
            state_var_offset,
            dispatch_block_addrs: targets.clone(),
            num_states: targets.len(),
            pattern: StateMachinePattern::SwitchDispatcher,
        })
    }

    /// Extract the state variable location from the dispatcher block.
    #[must_use]
    pub fn extract_state_variable(&self, dispatcher_addr: u64) -> Option<DispatchRead> {
        let block = self.blocks.get(&dispatcher_addr)?;
        block.dispatch_read.clone()
    }

    /// Build a state transition graph from the detected state blocks.
    ///
    /// Maps `state_id` → `Vec<next_state_id>`.
    #[must_use]
    pub fn build_state_transition_graph(
        &self,
        dispatcher: &DispatcherInfo,
    ) -> HashMap<u32, Vec<u32>> {
        let mut graph: HashMap<u32, Vec<u32>> = HashMap::new();

        for (idx, &block_addr) in dispatcher.dispatch_block_addrs.iter().enumerate() {
            let state_id = u32::try_from(idx).unwrap_or(u32::MAX);
            graph.entry(state_id).or_default();

            if let Some(block) = self.blocks.get(&block_addr) {
                for &succ_addr in &block.successors {
                    // Check if the successor is one of the dispatch targets
                    if let Some(succ_idx) = dispatcher
                        .dispatch_block_addrs
                        .iter()
                        .position(|&a| a == succ_addr)
                    {
                        graph.entry(state_id).or_default().push(u32::try_from(succ_idx).unwrap_or(u32::MAX));
                    }
                }
            }
        }

        graph
    }

    /// Compute the original linear state sequence by topological sort of the
    /// state transition graph (removing back edges = loop back-edges to dispatcher).
    ///
    /// # Errors
    ///
    /// Returns `Err` when the transition graph has an unresolvable cyclic dependency.
    pub fn compute_state_sequence(
        &self,
        transition_graph: &HashMap<u32, Vec<u32>>,
    ) -> Result<Vec<u32>, SmError> {
        // Kahn's algorithm
        let mut in_degree: HashMap<u32, usize> = HashMap::new();
        for &node in transition_graph.keys() {
            in_degree.entry(node).or_insert(0);
        }
        for successors in transition_graph.values() {
            for &succ in successors {
                *in_degree.entry(succ).or_insert(0) += 1;
            }
        }

        let mut queue: VecDeque<u32> = in_degree
            .iter()
            .filter(|&(_, &deg)| deg == 0)
            .map(|(&n, _)| n)
            .collect();
        // Sort for determinism
        let mut queue_vec: Vec<u32> = queue.into_iter().collect();
        queue_vec.sort_unstable();
        queue = queue_vec.into_iter().collect();

        let mut order = Vec::new();

        while let Some(node) = queue.pop_front() {
            order.push(node);
            if let Some(succs) = transition_graph.get(&node) {
                let mut next_batch: Vec<u32> = Vec::new();
                for &succ in succs {
                    let deg = in_degree.entry(succ).or_insert(0);
                    if *deg > 0 {
                        *deg -= 1;
                    }
                    if *deg == 0 {
                        next_batch.push(succ);
                    }
                }
                next_batch.sort_unstable();
                queue.extend(next_batch);
            }
        }

        if order.len() < transition_graph.len() {
            // Cycle detected — use DFS order for remaining nodes
            let in_order: HashSet<u32> = order.iter().copied().collect();
            let mut remaining: Vec<u32> = transition_graph
                .keys()
                .filter(|n| !in_order.contains(n))
                .copied()
                .collect();
            remaining.sort_unstable();
            order.extend(remaining);
        }

        Ok(order)
    }

    /// Build `StateBlock` descriptors for each dispatch target.
    #[must_use]
    pub fn build_state_blocks(&self, dispatcher: &DispatcherInfo) -> Vec<StateBlock> {
        let mut blocks = Vec::new();
        let transition_graph = self.build_state_transition_graph(dispatcher);

        for (idx, &block_addr) in dispatcher.dispatch_block_addrs.iter().enumerate() {
            let state_id = u32::try_from(idx).unwrap_or(u32::MAX);
            let next_states = transition_graph.get(&state_id).cloned().unwrap_or_default();
            let is_terminal = next_states.is_empty();

            let (instructions, real_successor) = self.blocks.get(&block_addr).map_or_else(
                || (Vec::new(), None),
                |block| {
                    let real_succ = block
                        .successors
                        .iter()
                        .find(|&&a| !dispatcher.dispatch_block_addrs.contains(&a) && a != dispatcher.dispatcher_addr)
                        .copied();
                    (block.instructions.clone(), real_succ)
                },
            );

            blocks.push(StateBlock {
                state_id,
                block_addr,
                next_states,
                is_terminal,
                real_successor,
                instructions,
            });
        }

        blocks
    }

    /// High-level analysis entry point: detect CFF and produce a report.
    #[must_use]
    pub fn analyse(&self) -> CffReport {
        let Ok(dispatcher) = self.detect_dispatcher() else {
            return CffReport {
                is_flattened: false,
                dispatcher_count: 0,
                state_count: 0,
                complexity_reduction: 0.0,
            };
        };

        let original_block_count = self.blocks.len();
        let state_count = u32::try_from(dispatcher.num_states).unwrap_or(u32::MAX);
        // Rough metric: a flattened function has N+2 blocks for N states
        let overhead = original_block_count.saturating_sub(dispatcher.num_states);
        let overhead_f = f64::from(u32::try_from(overhead).unwrap_or(u32::MAX));
        let complexity_reduction = if original_block_count > 0 {
            overhead_f / f64::from(u32::try_from(original_block_count).unwrap_or(1))
        } else {
            0.0
        };

        CffReport {
            is_flattened: true,
            dispatcher_count: 1,
            state_count,
            complexity_reduction,
        }
    }
}

impl Default for CffStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helper: compute_predecessors ─────────────────────────────────────────────

/// Build predecessor map from a successor-based adjacency map.
#[must_use]
pub fn compute_predecessors<S: std::hash::BuildHasher>(
    graph: &HashMap<u32, Vec<u32>, S>,
) -> HashMap<u32, Vec<u32>> {
    let mut pred: HashMap<u32, Vec<u32>> = HashMap::new();
    for (&node, succs) in graph {
        pred.entry(node).or_default();
        for &s in succs {
            pred.entry(s).or_default().push(node);
        }
    }
    pred
}

/// Detect back edges in a DFS traversal (edges that point to an ancestor).
#[must_use]
pub fn find_back_edges<S: std::hash::BuildHasher>(
    graph: &HashMap<u32, Vec<u32>, S>,
    entry: u32,
) -> Vec<(u32, u32)> {
    let mut visited = HashSet::new();
    let mut stack = HashSet::new();
    let mut back_edges = Vec::new();
    dfs_back_edges(entry, graph, &mut visited, &mut stack, &mut back_edges);
    back_edges
}

/// Maximum recursion depth for DFS back-edge detection.
/// Prevents stack overflow on adversarially deep CFGs.
const DFS_MAX_DEPTH: usize = 1024;

fn dfs_back_edges<S: std::hash::BuildHasher>(
    node: u32,
    graph: &HashMap<u32, Vec<u32>, S>,
    visited: &mut HashSet<u32>,
    stack: &mut HashSet<u32>,
    back_edges: &mut Vec<(u32, u32)>,
) {
    dfs_back_edges_inner(node, graph, visited, stack, back_edges, 0);
}

fn dfs_back_edges_inner<S: std::hash::BuildHasher>(
    node: u32,
    graph: &HashMap<u32, Vec<u32>, S>,
    visited: &mut HashSet<u32>,
    stack: &mut HashSet<u32>,
    back_edges: &mut Vec<(u32, u32)>,
    depth: usize,
) {
    if depth >= DFS_MAX_DEPTH {
        return;
    }
    if visited.contains(&node) {
        return;
    }
    visited.insert(node);
    stack.insert(node);
    if let Some(succs) = graph.get(&node) {
        for &succ in succs {
            if stack.contains(&succ) {
                back_edges.push((node, succ));
            } else {
                dfs_back_edges_inner(succ, graph, visited, stack, back_edges, depth + 1);
            }
        }
    }
    stack.remove(&node);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dispatcher_block(addr: u64, targets: Vec<u64>) -> BasicBlock {
        let mut b = BasicBlock::new(addr);
        b.switch_targets = targets.clone();
        b.successors = targets;
        b.dispatch_read = Some(DispatchRead { stack_offset: Some(-4), register: None });
        b
    }

    fn make_state_block(addr: u64, succs: Vec<u64>, depth: u32) -> BasicBlock {
        let mut b = BasicBlock::new(addr);
        b.successors = succs;
        b.loop_depth = depth;
        b
    }

    // 1. Detect dispatcher with 5 switch targets
    #[test]
    fn test_detect_dispatcher_basic() {
        let mut sm = CffStateMachine::new();
        let targets: Vec<u64> = (1u64..=5).map(|i| i * 0x100).collect();
        sm.add_block(make_dispatcher_block(0x1000, targets.clone()));
        for t in &targets {
            sm.add_block(make_state_block(*t, vec![0x1000], 0));
        }
        let info = sm.detect_dispatcher().unwrap();
        assert_eq!(info.dispatcher_addr, 0x1000);
        assert_eq!(info.num_states, 5);
    }

    // 2. Empty CFG returns EmptyCfg error
    #[test]
    fn test_empty_cfg_error() {
        let sm = CffStateMachine::new();
        assert!(matches!(sm.detect_dispatcher(), Err(SmError::EmptyCfg)));
    }

    // 3. Too few switch targets returns NoDispatcherFound
    #[test]
    fn test_too_few_targets() {
        let mut sm = CffStateMachine::new();
        let mut b = BasicBlock::new(0x1000);
        b.switch_targets = vec![0x100, 0x200]; // only 2 targets
        sm.add_block(b);
        assert!(matches!(sm.detect_dispatcher(), Err(SmError::NoDispatcherFound)));
    }

    // 4. extract_state_variable returns offset
    #[test]
    fn test_extract_state_variable() {
        let mut sm = CffStateMachine::new();
        let b = make_dispatcher_block(0x1000, vec![0x100, 0x200, 0x300, 0x400, 0x500]);
        sm.add_block(b);
        let dr = sm.extract_state_variable(0x1000).unwrap();
        assert_eq!(dr.stack_offset, Some(-4));
    }

    // 5. extract_state_variable returns None for unknown block
    #[test]
    fn test_extract_state_variable_unknown() {
        let sm = CffStateMachine::new();
        assert!(sm.extract_state_variable(0xdead_beef).is_none());
    }

    // 6. build_state_transition_graph maps states to successors
    #[test]
    fn test_build_transition_graph() {
        let mut sm = CffStateMachine::new();
        let targets: Vec<u64> = (0u64..5).map(|i| 0x100 + i * 0x100).collect();
        sm.add_block(make_dispatcher_block(0x1000, targets.clone()));
        // State 0 → state 1
        let mut b0 = make_state_block(targets[0], vec![targets[1], 0x1000], 0);
        b0.loop_depth = 0;
        sm.add_block(b0);
        for t in &targets[1..] {
            sm.add_block(make_state_block(*t, vec![0x1000], 0));
        }
        let info = sm.detect_dispatcher().unwrap();
        let graph = sm.build_state_transition_graph(&info);
        // State 0 should have successor 1
        let succs = graph.get(&0).unwrap();
        assert!(succs.contains(&1));
    }

    // 7. compute_state_sequence linear chain
    #[test]
    fn test_compute_state_sequence_linear() {
        let mut graph = HashMap::new();
        graph.insert(0u32, vec![1u32]);
        graph.insert(1, vec![2]);
        graph.insert(2, vec![]);
        let sm = CffStateMachine::new();
        let seq = sm.compute_state_sequence(&graph).unwrap();
        assert_eq!(seq, vec![0, 1, 2]);
    }

    // 8. compute_state_sequence handles empty graph
    #[test]
    fn test_compute_state_sequence_empty() {
        let sm = CffStateMachine::new();
        let seq = sm.compute_state_sequence(&HashMap::new()).unwrap();
        assert!(seq.is_empty());
    }

    // 9. analyse returns is_flattened = true for flattened CFG
    #[test]
    fn test_analyse_is_flattened() {
        let mut sm = CffStateMachine::new();
        let targets: Vec<u64> = (0u64..6).map(|i| 0x200 + i * 0x100).collect();
        sm.add_block(make_dispatcher_block(0x1000, targets.clone()));
        for t in &targets {
            sm.add_block(make_state_block(*t, vec![0x1000], 0));
        }
        let report = sm.analyse();
        assert!(report.is_flattened);
        assert_eq!(report.state_count, 6);
    }

    // 10. analyse returns is_flattened = false for flat CFG
    #[test]
    fn test_analyse_not_flattened() {
        let mut sm = CffStateMachine::new();
        // Only two blocks, linear
        let mut b0 = BasicBlock::new(0x1000);
        b0.successors = vec![0x2000];
        let mut b1 = BasicBlock::new(0x2000);
        b1.successors = vec![];
        sm.add_block(b0);
        sm.add_block(b1);
        let report = sm.analyse();
        assert!(!report.is_flattened);
    }

    // 11. build_state_blocks produces correct count
    #[test]
    fn test_build_state_blocks_count() {
        let mut sm = CffStateMachine::new();
        let targets: Vec<u64> = (0u64..5).map(|i| 0x100 + i * 0x10).collect();
        sm.add_block(make_dispatcher_block(0x1000, targets.clone()));
        for t in &targets {
            sm.add_block(make_state_block(*t, vec![], 0));
        }
        let info = sm.detect_dispatcher().unwrap();
        let blocks = sm.build_state_blocks(&info);
        assert_eq!(blocks.len(), 5);
    }

    // 12. Terminal state has no next_states
    #[test]
    fn test_terminal_state() {
        let mut sm = CffStateMachine::new();
        let targets: Vec<u64> = vec![0x100, 0x200, 0x300, 0x400, 0x500];
        sm.add_block(make_dispatcher_block(0x1000, targets.clone()));
        for t in &targets {
            sm.add_block(make_state_block(*t, vec![], 0));
        }
        let info = sm.detect_dispatcher().unwrap();
        let blocks = sm.build_state_blocks(&info);
        assert!(blocks.iter().all(|b| b.is_terminal));
    }

    // 13. compute_predecessors correctly inverts graph
    #[test]
    fn test_compute_predecessors() {
        let mut graph = HashMap::new();
        graph.insert(0u32, vec![1u32, 2u32]);
        graph.insert(1, vec![]);
        graph.insert(2, vec![]);
        let pred = compute_predecessors(&graph);
        assert!(pred.get(&1).unwrap().contains(&0));
        assert!(pred.get(&2).unwrap().contains(&0));
    }

    // 14. find_back_edges detects loop
    #[test]
    fn test_find_back_edges() {
        let mut graph = HashMap::new();
        graph.insert(0u32, vec![1u32]);
        graph.insert(1, vec![2]);
        graph.insert(2, vec![0]); // back edge 2 → 0
        let back = find_back_edges(&graph, 0);
        assert!(back.contains(&(2, 0)));
    }

    // 15. state_var_offset propagated in dispatcher info
    #[test]
    fn test_state_var_offset_propagated() {
        let mut sm = CffStateMachine::new();
        let targets: Vec<u64> = (0u64..5).map(|i| i * 0x100 + 0x500).collect();
        let mut disp = make_dispatcher_block(0x1000, targets);
        disp.dispatch_read = Some(DispatchRead { stack_offset: Some(-8), register: None });
        sm.add_block(disp);
        let info = sm.detect_dispatcher().unwrap();
        assert_eq!(info.state_var_offset, Some(-8));
    }
}
