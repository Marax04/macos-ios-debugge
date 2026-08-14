//! CFF decompiler: recover structured control flow from a de-flattened CFG.
//!
//! After [`StateMachineExtractor`] produces a [`RecoveredCfg`] this module
//! performs a second pass to:
//!
//! 1. Identify natural loops in the recovered CFG.
//! 2. Identify if/else regions.
//! 3. Eliminate the synthetic dispatcher block and state-variable assignments.
//! 4. Produce a [`DecompiledFunction`] – an ordered list of [`RecoveredBlock`]
//!    entries annotated with their structural role.

use std::collections::{HashMap, HashSet, VecDeque};

// Re-export the types produced by the state_machine_extractor that we build on.
use crate::state_machine_extractor::{RecoveredBlock, RecoveredCfg};

// ─────────────────────────────────────────────────────────────────────────────
// DecompState — per-block structural annotation
// ─────────────────────────────────────────────────────────────────────────────

/// The structural role of a recovered block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompState {
    /// Plain sequential block.
    Linear,
    /// Conditional branch head (if / if-else).
    IfHead,
    /// The "true" arm of a conditional.
    IfTrue,
    /// The "false" arm of a conditional.
    IfFalse,
    /// Merge point after an if/if-else.
    IfMerge,
    /// Natural loop header.
    LoopHeader,
    /// Block inside a loop body.
    LoopBody,
    /// The back-edge source (last block of a loop iteration).
    LoopLatch,
    /// Function return block.
    Return,
    /// Unreachable / dead block.
    Dead,
}

// ─────────────────────────────────────────────────────────────────────────────
// RecoveredBlockAnnotated
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered basic block together with its structural role.
#[derive(Debug, Clone)]
pub struct RecoveredBlockAnnotated {
    pub id: u64,
    pub successors: Vec<u64>,
    pub is_conditional: bool,
    pub instruction_count: usize,
    pub state: DecompState,
    /// Which loop (header block id) does this block belong to?
    pub loop_id: Option<u64>,
}

impl RecoveredBlockAnnotated {
    fn from_recovered(b: &RecoveredBlock) -> Self {
        Self {
            id: b.id,
            successors: b.successors.clone(),
            is_conditional: b.is_conditional,
            instruction_count: b.instruction_count,
            state: DecompState::Linear,
            loop_id: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// A natural loop identified in the recovered CFG.
#[derive(Debug, Clone)]
pub struct LoopRecovery {
    /// The loop header (target of back-edges).
    pub header: u64,
    /// All blocks in the loop body (including header).
    pub body: HashSet<u64>,
    /// The back-edge source (latch block).
    pub latch: u64,
    /// The block immediately after the loop (the exit).
    pub exit: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// IfElseRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// An if/if-else region identified in the recovered CFG.
#[derive(Debug, Clone)]
pub struct IfElseRecovery {
    pub head: u64,
    pub true_branch: Vec<u64>,
    pub false_branch: Vec<u64>,
    /// The merge block (post-dominator of head, or `None` for if-without-else).
    pub merge: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// DecompiledFunction
// ─────────────────────────────────────────────────────────────────────────────

/// Output of the CFF decompiler: a structurally annotated function.
#[derive(Debug)]
pub struct DecompiledFunction {
    pub entry_id: u64,
    pub blocks: HashMap<u64, RecoveredBlockAnnotated>,
    pub loops: Vec<LoopRecovery>,
    pub if_regions: Vec<IfElseRecovery>,
    /// Topological order of blocks (entry first).
    pub topo_order: Vec<u64>,
    /// Number of unresolved blocks (blocks whose successors are still unknown).
    pub unresolved_count: usize,
}

impl DecompiledFunction {
    #[must_use]
    pub fn block_count(&self) -> usize { self.blocks.len() }
    #[must_use]
    pub const fn loop_count(&self) -> usize { self.loops.len() }
    #[must_use]
    pub const fn if_count(&self) -> usize { self.if_regions.len() }
}

// ─────────────────────────────────────────────────────────────────────────────
// CffDecompiler
// ─────────────────────────────────────────────────────────────────────────────

/// Main decompiler: converts a [`RecoveredCfg`] into a [`DecompiledFunction`].
#[derive(Debug, Default)]
pub struct CffDecompiler;

impl CffDecompiler {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Run the full decompilation pipeline.
    #[must_use]
    pub fn decompile(&self, cfg: &RecoveredCfg) -> DecompiledFunction {
        // Annotate blocks
        let mut blocks: HashMap<u64, RecoveredBlockAnnotated> = cfg
            .blocks
            .values()
            .map(|b| (b.id, RecoveredBlockAnnotated::from_recovered(b)))
            .collect();

        // Mark return blocks
        for b in blocks.values_mut() {
            if b.successors.is_empty() {
                b.state = DecompState::Return;
            }
        }

        // Compute topological order
        let topo_order = Self::topo_sort(cfg.entry_id, &blocks);

        // Detect loops
        let loops = Self::detect_loops(cfg.entry_id, &blocks);

        // Annotate loop blocks
        for lrec in &loops {
            if let Some(b) = blocks.get_mut(&lrec.header) {
                b.state = DecompState::LoopHeader;
                b.loop_id = Some(lrec.header);
            }
            if let Some(b) = blocks.get_mut(&lrec.latch) {
                if b.state == DecompState::Linear { b.state = DecompState::LoopLatch; }
                b.loop_id = Some(lrec.header);
            }
            for &body_id in &lrec.body {
                if let Some(b) = blocks.get_mut(&body_id)
                    && b.state == DecompState::Linear
                {
                    b.state = DecompState::LoopBody;
                    b.loop_id = Some(lrec.header);
                }
            }
        }

        // Detect if/else regions
        let if_regions = Self::detect_if_else(cfg.entry_id, &blocks, &loops);

        // Annotate if blocks
        for ifrec in &if_regions {
            if let Some(b) = blocks.get_mut(&ifrec.head)
                && (b.state == DecompState::Linear || b.state == DecompState::LoopBody)
            {
                b.state = DecompState::IfHead;
            }
            for &id in &ifrec.true_branch {
                if let Some(b) = blocks.get_mut(&id) && b.state == DecompState::Linear {
                    b.state = DecompState::IfTrue;
                }
            }
            for &id in &ifrec.false_branch {
                if let Some(b) = blocks.get_mut(&id) && b.state == DecompState::Linear {
                    b.state = DecompState::IfFalse;
                }
            }
            if let Some(merge_id) = ifrec.merge
                && let Some(b) = blocks.get_mut(&merge_id)
                && b.state == DecompState::Linear
            {
                b.state = DecompState::IfMerge;
            }
        }

        DecompiledFunction {
            entry_id: cfg.entry_id,
            blocks,
            loops,
            if_regions,
            topo_order,
            unresolved_count: cfg.unresolved_blocks.len(),
        }
    }

    // ── Topological sort (Kahn's algorithm) ──────────────────────────────────

    fn topo_sort(entry: u64, blocks: &HashMap<u64, RecoveredBlockAnnotated>) -> Vec<u64> {
        // In-degree map
        let mut in_degree: HashMap<u64, usize> = blocks.keys().map(|&id| (id, 0)).collect();
        for b in blocks.values() {
            for &s in &b.successors {
                *in_degree.entry(s).or_insert(0) += 1;
            }
        }

        let mut queue: VecDeque<u64> = in_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(&id, _)| id)
            .collect();

        // Ensure entry is first
        if !queue.contains(&entry) { queue.push_front(entry); }

        let mut order = Vec::new();
        let mut visited = HashSet::new();
        // Process entry first
        queue.retain(|&id| id != entry);
        queue.push_front(entry);

        while let Some(id) = queue.pop_front() {
            if !visited.insert(id) { continue; }
            order.push(id);
            if let Some(b) = blocks.get(&id) {
                for &s in &b.successors {
                    if let Some(d) = in_degree.get_mut(&s) {
                        *d = d.saturating_sub(1);
                        if *d == 0 { queue.push_back(s); }
                    }
                }
            }
        }

        // Append any remaining (part of cycles)
        for &id in blocks.keys() {
            if !visited.contains(&id) { order.push(id); }
        }
        order
    }

    // ── Loop detection (DFS back-edge method) ────────────────────────────────

    fn detect_loops(
        entry: u64,
        blocks: &HashMap<u64, RecoveredBlockAnnotated>,
    ) -> Vec<LoopRecovery> {
        let mut loops = Vec::new();
        let mut visited = HashSet::new();
        let mut stack: HashSet<u64> = HashSet::new();
        let mut back_edges: Vec<(u64, u64)> = Vec::new(); // (latch, header)

        Self::dfs_back_edges(entry, blocks, &mut visited, &mut stack, &mut back_edges);

        for (latch, header) in back_edges {
            let body = Self::natural_loop_body(header, latch, blocks);
            let exit = Self::loop_exit(&body, blocks);
            loops.push(LoopRecovery { header, body, latch, exit });
        }
        loops
    }

    /// Maximum recursion depth for DFS back-edge detection.
    /// Prevents stack overflow on adversarially deep recovered CFGs.
    const DFS_MAX_DEPTH: usize = 1024;

    fn dfs_back_edges(
        node: u64,
        blocks: &HashMap<u64, RecoveredBlockAnnotated>,
        visited: &mut HashSet<u64>,
        stack: &mut HashSet<u64>,
        back_edges: &mut Vec<(u64, u64)>,
    ) {
        Self::dfs_back_edges_inner(node, blocks, visited, stack, back_edges, 0);
    }

    fn dfs_back_edges_inner(
        node: u64,
        blocks: &HashMap<u64, RecoveredBlockAnnotated>,
        visited: &mut HashSet<u64>,
        stack: &mut HashSet<u64>,
        back_edges: &mut Vec<(u64, u64)>,
        depth: usize,
    ) {
        if depth >= Self::DFS_MAX_DEPTH {
            return;
        }
        if visited.contains(&node) { return; }
        visited.insert(node);
        stack.insert(node);
        if let Some(b) = blocks.get(&node) {
            for &s in &b.successors {
                if stack.contains(&s) {
                    back_edges.push((node, s));
                } else {
                    Self::dfs_back_edges_inner(s, blocks, visited, stack, back_edges, depth + 1);
                }
            }
        }
        stack.remove(&node);
    }

    fn natural_loop_body(
        header: u64,
        latch: u64,
        blocks: &HashMap<u64, RecoveredBlockAnnotated>,
    ) -> HashSet<u64> {
        let mut body = HashSet::new();
        body.insert(header);
        body.insert(latch);
        let mut queue = VecDeque::new();
        queue.push_back(latch);
        while let Some(id) = queue.pop_front() {
            if let Some(_b) = blocks.get(&id) {
                for &pred_id in blocks.values()
                    .filter(|bb| bb.successors.contains(&id))
                    .map(|bb| &bb.id)
                {
                    if body.insert(pred_id) && pred_id != header {
                        queue.push_back(pred_id);
                    }
                }
            }
        }
        body
    }

    fn loop_exit(
        body: &HashSet<u64>,
        blocks: &HashMap<u64, RecoveredBlockAnnotated>,
    ) -> Option<u64> {
        for &id in body {
            if let Some(b) = blocks.get(&id) {
                for &s in &b.successors {
                    if !body.contains(&s) { return Some(s); }
                }
            }
        }
        None
    }

    // ── If/else detection ────────────────────────────────────────────────────

    fn detect_if_else(
        entry: u64,
        blocks: &HashMap<u64, RecoveredBlockAnnotated>,
        loops: &[LoopRecovery],
    ) -> Vec<IfElseRecovery> {
        let loop_headers: HashSet<u64> = loops.iter().map(|l| l.header).collect();
        let mut result = Vec::new();
        let topo = Self::topo_sort(entry, blocks);

        for &head_id in &topo {
            let Some(head) = blocks.get(&head_id) else { continue };
            if head.successors.len() != 2 { continue; }
            if loop_headers.contains(&head_id) { continue; }

            let (a, b) = (head.successors[0], head.successors[1]);

            // Simple if/else: find merge block (common successor)
            let succs_a: HashSet<u64> = Self::reachable_within(a, blocks, 8);
            let succs_b: HashSet<u64> = Self::reachable_within(b, blocks, 8);
            let merge_candidates: HashSet<u64> = succs_a.intersection(&succs_b).copied().collect();

            let merge = merge_candidates.iter()
                .copied()
                .find(|&id| id != a && id != b && id != head_id);

            let (true_arm, false_arm) = merge.map_or_else(
                || (vec![a], vec![b]),
                |m| {
                    let ta: Vec<u64> = succs_a.iter().copied()
                        .filter(|&id| id != m && id != head_id).collect();
                    let fa: Vec<u64> = succs_b.iter().copied()
                        .filter(|&id| id != m && id != head_id).collect();
                    (ta, fa)
                },
            );

            result.push(IfElseRecovery {
                head: head_id,
                true_branch: true_arm,
                false_branch: false_arm,
                merge,
            });
        }
        result
    }

    /// BFS up to `depth` hops from `start`, returning all reachable IDs.
    fn reachable_within(
        start: u64,
        blocks: &HashMap<u64, RecoveredBlockAnnotated>,
        depth: usize,
    ) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((start, 0usize));
        while let Some((id, d)) = queue.pop_front() {
            if !visited.insert(id) || d >= depth { continue; }
            if let Some(b) = blocks.get(&id) {
                for &s in &b.successors { queue.push_back((s, d + 1)); }
            }
        }
        visited
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine_extractor::RecoveredBlock;

    fn make_cfg(
        entry: u64,
        blocks: Vec<(u64, Vec<u64>)>,  // (id, successors)
    ) -> RecoveredCfg {
        let mut cfg = RecoveredCfg { entry_id: entry, ..Default::default() };
        for (id, succs) in blocks {
            cfg.blocks.insert(id, RecoveredBlock {
                id,
                successors: succs.clone(),
                is_conditional: succs.len() > 1,
                instruction_count: 5,
                original_state: None,
            });
        }
        cfg
    }

    #[test]
    fn test_linear_function() {
        let cfg = make_cfg(0, vec![(0, vec![1]), (1, vec![2]), (2, vec![])]);
        let dec = CffDecompiler::new().decompile(&cfg);
        assert_eq!(dec.block_count(), 3);
        assert_eq!(dec.loop_count(), 0);
        assert_eq!(dec.if_count(), 0);
        assert_eq!(dec.blocks[&2].state, DecompState::Return);
    }

    #[test]
    fn test_if_else_detected() {
        // 0 → 1, 2 (branch); 1 → 3; 2 → 3; 3 → (exit)
        let cfg = make_cfg(0, vec![
            (0, vec![1, 2]),
            (1, vec![3]),
            (2, vec![3]),
            (3, vec![]),
        ]);
        let dec = CffDecompiler::new().decompile(&cfg);
        assert_eq!(dec.if_count(), 1);
        let ifrec = &dec.if_regions[0];
        assert_eq!(ifrec.head, 0);
        assert_eq!(ifrec.merge, Some(3));
    }

    #[test]
    fn test_loop_detected() {
        // 0 → 1 → 2 → 1 (loop back); 2 → 3 (exit)
        let cfg = make_cfg(0, vec![
            (0, vec![1]),
            (1, vec![2]),
            (2, vec![1, 3]),
            (3, vec![]),
        ]);
        let dec = CffDecompiler::new().decompile(&cfg);
        assert_eq!(dec.loop_count(), 1);
        assert_eq!(dec.loops[0].header, 1);
    }

    #[test]
    fn test_topo_order_starts_with_entry() {
        let cfg = make_cfg(0, vec![(0, vec![1]), (1, vec![2]), (2, vec![])]);
        let dec = CffDecompiler::new().decompile(&cfg);
        assert_eq!(dec.topo_order[0], 0);
    }

    #[test]
    fn test_loop_header_annotated() {
        let cfg = make_cfg(0, vec![
            (0, vec![1]),
            (1, vec![2]),
            (2, vec![1, 3]),
            (3, vec![]),
        ]);
        let dec = CffDecompiler::new().decompile(&cfg);
        assert_eq!(dec.blocks[&1].state, DecompState::LoopHeader);
    }

    #[test]
    fn test_return_block_annotated() {
        let cfg = make_cfg(0, vec![(0, vec![1]), (1, vec![])]);
        let dec = CffDecompiler::new().decompile(&cfg);
        assert_eq!(dec.blocks[&1].state, DecompState::Return);
    }

    #[test]
    fn test_unresolved_propagated() {
        let mut cfg = make_cfg(0, vec![(0, vec![1]), (1, vec![])]);
        cfg.unresolved_blocks.push(0);
        let dec = CffDecompiler::new().decompile(&cfg);
        assert_eq!(dec.unresolved_count, 1);
    }
}
