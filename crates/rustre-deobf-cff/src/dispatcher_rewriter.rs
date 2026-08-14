//! CFF dispatcher block rewriter.
//!
//! Given a set of `RewriteAction`s produced by the analysis pass, this module
//! applies them to a `Cfg`, validates the result, and computes a diff between
//! snapshots.

use std::collections::{HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// BasicBlock (minimal, self-contained for this module)
// ---------------------------------------------------------------------------

/// A basic block used in this module's CFG representation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BasicBlock {
    pub addr: u64,
    pub insns: Vec<u8>,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
}

impl BasicBlock {
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self {
            addr,
            insns: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Cfg
// ---------------------------------------------------------------------------

/// A simple control-flow graph: map of block address → block + explicit edge list.
#[derive(Debug, Clone, Default)]
pub struct Cfg {
    pub blocks: HashMap<u64, BasicBlock>,
    pub entry: u64,
}

impl Cfg {
    #[must_use]
    pub fn new(entry: u64) -> Self {
        Self { blocks: HashMap::new(), entry }
    }

    pub fn add_block(&mut self, block: BasicBlock) {
        self.blocks.insert(block.addr, block);
    }

    pub fn add_edge(&mut self, from: u64, to: u64) {
        if let Some(b) = self.blocks.get_mut(&from) && !b.successors.contains(&to) {
            b.successors.push(to);
        }
        if let Some(b) = self.blocks.get_mut(&to) && !b.predecessors.contains(&from) {
            b.predecessors.push(from);
        }
    }

    pub fn remove_edge(&mut self, from: u64, to: u64) {
        if let Some(b) = self.blocks.get_mut(&from) {
            b.successors.retain(|&s| s != to);
        }
        if let Some(b) = self.blocks.get_mut(&to) {
            b.predecessors.retain(|&p| p != from);
        }
    }

    #[must_use]
    pub fn edges(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for (addr, block) in &self.blocks {
            for &succ in &block.successors {
                out.push((*addr, succ));
            }
        }
        out
    }

    /// BFS reachability from entry.
    #[must_use]
    pub fn reachable_from_entry(&self) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(self.entry);
        while let Some(addr) = queue.pop_front() {
            if visited.insert(addr) {
                if let Some(block) = self.blocks.get(&addr) {
                    for &succ in &block.successors {
                        if !visited.contains(&succ) {
                            queue.push_back(succ);
                        }
                    }
                }
            }
        }
        visited
    }
}

// ---------------------------------------------------------------------------
// RewriteAction
// ---------------------------------------------------------------------------

/// A single atomic change to be applied to a CFG.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RewriteAction {
    RemoveBlock(u64),
    AddEdge(u64, u64),
    RemoveEdge(u64, u64),
    ReplaceBlock { addr: u64, new_insns: Vec<u8> },
    MergeBlocks { a: u64, b: u64 },
}

// ---------------------------------------------------------------------------
// RewriteResult
// ---------------------------------------------------------------------------

/// Summary of a rewrite pass.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RewriteResult {
    pub actions: Vec<RewriteAction>,
    pub simplified_block_count: u32,
    pub removed_dispatcher_blocks: Vec<u64>,
}

impl RewriteResult {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_action(&mut self, action: RewriteAction) {
        if let RewriteAction::RemoveBlock(addr) = &action {
            self.removed_dispatcher_blocks.push(*addr);
            self.simplified_block_count += 1;
        }
        self.actions.push(action);
    }
}

// ---------------------------------------------------------------------------
// CfgSnapshot
// ---------------------------------------------------------------------------

/// Immutable snapshot of a CFG state for diffing.
#[derive(Debug, Clone)]
pub struct CfgSnapshot {
    pub blocks: HashMap<u64, BasicBlock>,
    pub edges: Vec<(u64, u64)>,
    pub entry: u64,
}

impl CfgSnapshot {
    #[must_use]
    pub fn capture(cfg: &Cfg) -> Self {
        Self {
            blocks: cfg.blocks.clone(),
            edges: cfg.edges(),
            entry: cfg.entry,
        }
    }
}

// ---------------------------------------------------------------------------
// DispatcherRewriter
// ---------------------------------------------------------------------------

/// The top-level rewriter: detects dispatcher blocks, builds a `RewriteResult`,
/// and applies it.
#[derive(Debug, Default)]
pub struct DispatcherRewriter {
    /// Minimum number of successors for a block to be considered a dispatcher.
    pub min_dispatcher_successors: usize,
}

impl DispatcherRewriter {
    #[must_use]
    pub const fn new() -> Self {
        Self { min_dispatcher_successors: 2 }
    }

    // -----------------------------------------------------------------------
    // Dispatcher detection
    // -----------------------------------------------------------------------

    /// Heuristically identify dispatcher blocks: blocks with many successors
    /// whose instructions look like a switch dispatch (small code body).
    #[must_use]
    pub fn find_dispatcher_blocks(&self, cfg: &Cfg) -> Vec<u64> {
        cfg.blocks
            .values()
            .filter(|b| b.successors.len() >= self.min_dispatcher_successors)
            .map(|b| b.addr)
            .collect()
    }

    /// For a dispatcher at `dispatcher_addr`, find all *real* state blocks
    /// (i.e. successors that have predecessors only from the dispatcher).
    #[must_use]
    pub fn find_state_blocks(&self, cfg: &Cfg, dispatcher_addr: u64) -> Vec<u64> {
        let Some(dispatcher) = cfg.blocks.get(&dispatcher_addr) else {
            return Vec::new();
        };
        dispatcher
            .successors
            .iter()
            .filter(|&&succ| {
                cfg.blocks.get(&succ).is_some_and(|b| {
                    // A real state block has at most one predecessor (the dispatcher)
                    // or comes exclusively from the dispatcher.
                    b.predecessors.iter().all(|&p| p == dispatcher_addr)
                })
            })
            .copied()
            .collect()
    }

    // -----------------------------------------------------------------------
    // remove_dispatcher_block
    // -----------------------------------------------------------------------

    /// Build rewrite actions to remove a single dispatcher block and reconnect
    /// each state block directly to its successors.
    #[must_use]
    pub fn remove_dispatcher_block(
        &self,
        cfg: &Cfg,
        dispatcher_addr: u64,
    ) -> RewriteResult {
        let mut result = RewriteResult::new();
        let Some(dispatcher) = cfg.blocks.get(&dispatcher_addr) else {
            return result;
        };

        // For each predecessor of the dispatcher, add edges directly to
        // each of the dispatcher's successors.
        let preds: Vec<u64> = dispatcher.predecessors.clone();
        let succs: Vec<u64> = dispatcher.successors.clone();

        for &pred in &preds {
            result.add_action(RewriteAction::RemoveEdge(pred, dispatcher_addr));
            for &succ in &succs {
                result.add_action(RewriteAction::AddEdge(pred, succ));
            }
        }

        // Remove all edges from dispatcher to successors
        for &succ in &succs {
            result.add_action(RewriteAction::RemoveEdge(dispatcher_addr, succ));
        }

        result.add_action(RewriteAction::RemoveBlock(dispatcher_addr));
        result
    }

    // -----------------------------------------------------------------------
    // inline_state_sequence
    // -----------------------------------------------------------------------

    /// If two blocks form a linear chain (A → B, B has only A as predecessor),
    /// merge them.
    #[must_use]
    pub fn inline_state_sequence(&self, cfg: &Cfg) -> RewriteResult {
        let mut result = RewriteResult::new();
        for (addr, block) in &cfg.blocks {
            if block.successors.len() == 1 {
                let succ_addr = block.successors[0];
                if let Some(succ) = cfg.blocks.get(&succ_addr)
                    && succ.predecessors.len() == 1
                    && succ.predecessors[0] == *addr
                {
                    result.add_action(RewriteAction::MergeBlocks {
                        a: *addr,
                        b: succ_addr,
                    });
                }
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // apply_actions
    // -----------------------------------------------------------------------

    /// Apply a list of `RewriteAction`s to a `Cfg` in order.
    ///
    /// Returns `true` if all actions were applied without structural errors.
    pub fn apply_actions(&self, cfg: &mut Cfg, actions: &[RewriteAction]) -> bool {
        let mut ok = true;
        for action in actions {
            match action {
                RewriteAction::RemoveBlock(addr) => {
                    if cfg.blocks.remove(addr).is_none() {
                        ok = false;
                    }
                }
                RewriteAction::AddEdge(from, to) => {
                    if cfg.blocks.contains_key(from) && cfg.blocks.contains_key(to) {
                        cfg.add_edge(*from, *to);
                    } else {
                        ok = false;
                    }
                }
                RewriteAction::RemoveEdge(from, to) => {
                    cfg.remove_edge(*from, *to);
                }
                RewriteAction::ReplaceBlock { addr, new_insns } => {
                    if let Some(block) = cfg.blocks.get_mut(addr) {
                        block.insns.clone_from(new_insns);
                    } else {
                        ok = false;
                    }
                }
                RewriteAction::MergeBlocks { a, b } => {
                    // Take insns from b and append to a; redirect a's successors
                    let b_insns: Vec<u8>;
                    let b_succs: Vec<u64>;
                    {
                        let Some(block_b) = cfg.blocks.get(b) else {
                            ok = false;
                            continue;
                        };
                        b_insns = block_b.insns.clone();
                        b_succs = block_b.successors.clone();
                    }
                    if let Some(block_a) = cfg.blocks.get_mut(a) {
                        block_a.insns.extend_from_slice(&b_insns);
                        block_a.successors.clone_from(&b_succs);
                    } else {
                        ok = false;
                        continue;
                    }
                    // Update predecessors of b's successors
                    for succ in &b_succs {
                        if let Some(s_block) = cfg.blocks.get_mut(succ) {
                            s_block.predecessors.retain(|&p| p != *b);
                            if !s_block.predecessors.contains(a) {
                                s_block.predecessors.push(*a);
                            }
                        }
                    }
                    cfg.blocks.remove(b);
                }
            }
        }
        ok
    }

    // -----------------------------------------------------------------------
    // validate_result
    // -----------------------------------------------------------------------

    /// Validate a CFG post-rewrite. Returns a list of error strings.
    #[must_use]
    pub fn validate_result(&self, cfg: &Cfg) -> Vec<String> {
        let mut errors = Vec::new();

        // Entry must exist
        if !cfg.blocks.contains_key(&cfg.entry) {
            errors.push(format!("entry block {:#x} missing", cfg.entry));
        }

        // All successors must refer to existing blocks
        for (addr, block) in &cfg.blocks {
            for &succ in &block.successors {
                if !cfg.blocks.contains_key(&succ) {
                    errors.push(format!("block {addr:#x} has successor {succ:#x} that does not exist"));
                }
            }
            // No duplicate successors
            let mut seen: HashSet<u64> = HashSet::new();
            for &succ in &block.successors {
                if !seen.insert(succ) {
                    errors.push(format!("block {addr:#x} has duplicate successor {succ:#x}"));
                }
            }
        }

        // All blocks should be reachable from entry
        let reachable = cfg.reachable_from_entry();
        for addr in cfg.blocks.keys() {
            if !reachable.contains(addr) {
                errors.push(format!("block {addr:#x} is unreachable from entry"));
            }
        }

        errors
    }

    // -----------------------------------------------------------------------
    // diff_snapshots
    // -----------------------------------------------------------------------

    /// Compute a `RewriteResult` summarising the difference between two CFG
    /// snapshots.
    #[must_use]
    pub fn diff_snapshots(
        &self,
        before: &CfgSnapshot,
        after: &CfgSnapshot,
    ) -> RewriteResult {
        let mut result = RewriteResult::new();

        // Blocks removed
        for addr in before.blocks.keys() {
            if !after.blocks.contains_key(addr) {
                result.add_action(RewriteAction::RemoveBlock(*addr));
            }
        }

        // Edges added
        let before_edges: HashSet<(u64, u64)> = before.edges.iter().copied().collect();
        let after_edges: HashSet<(u64, u64)> = after.edges.iter().copied().collect();
        for &edge in &after_edges {
            if !before_edges.contains(&edge) {
                result.add_action(RewriteAction::AddEdge(edge.0, edge.1));
            }
        }
        // Edges removed
        for &edge in &before_edges {
            if !after_edges.contains(&edge) {
                result.add_action(RewriteAction::RemoveEdge(edge.0, edge.1));
            }
        }

        // Blocks whose instructions changed
        for (addr, after_block) in &after.blocks {
            if let Some(before_block) = before.blocks.get(addr) {
                if before_block.insns != after_block.insns {
                    result.add_action(RewriteAction::ReplaceBlock {
                        addr: *addr,
                        new_insns: after_block.insns.clone(),
                    });
                }
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_cfg() -> Cfg {
        let mut cfg = Cfg::new(0x100);
        let entry = BasicBlock::new(0x100);
        let disp  = BasicBlock::new(0x200);
        let s1    = BasicBlock::new(0x300);
        let s2    = BasicBlock::new(0x400);
        cfg.add_block(entry);
        cfg.add_block(disp);
        cfg.add_block(s1);
        cfg.add_block(s2);
        cfg.add_edge(0x100, 0x200);
        cfg.add_edge(0x200, 0x300);
        cfg.add_edge(0x200, 0x400);
        cfg
    }

    #[test]
    fn find_dispatcher() {
        let cfg = simple_cfg();
        let rw = DispatcherRewriter::new();
        let disps = rw.find_dispatcher_blocks(&cfg);
        assert!(disps.contains(&0x200));
    }

    #[test]
    fn remove_dispatcher_adds_direct_edges() {
        let cfg = simple_cfg();
        let rw = DispatcherRewriter::new();
        let result = rw.remove_dispatcher_block(&cfg, 0x200);
        let has_direct_edge = result.actions.iter().any(|a| {
            matches!(a, RewriteAction::AddEdge(0x100, 0x300))
        });
        assert!(has_direct_edge);
    }

    #[test]
    fn remove_dispatcher_removes_block() {
        let cfg = simple_cfg();
        let rw = DispatcherRewriter::new();
        let result = rw.remove_dispatcher_block(&cfg, 0x200);
        assert!(result.removed_dispatcher_blocks.contains(&0x200));
    }

    #[test]
    fn apply_actions_add_edge() {
        let mut cfg = simple_cfg();
        let rw = DispatcherRewriter::new();
        let actions = vec![RewriteAction::AddEdge(0x100, 0x400)];
        assert!(rw.apply_actions(&mut cfg, &actions));
        assert!(cfg.blocks[&0x100].successors.contains(&0x400));
    }

    #[test]
    fn apply_actions_remove_edge() {
        let mut cfg = simple_cfg();
        let rw = DispatcherRewriter::new();
        let actions = vec![RewriteAction::RemoveEdge(0x200, 0x300)];
        rw.apply_actions(&mut cfg, &actions);
        assert!(!cfg.blocks[&0x200].successors.contains(&0x300));
    }

    #[test]
    fn apply_actions_remove_block() {
        let mut cfg = simple_cfg();
        let rw = DispatcherRewriter::new();
        let actions = vec![RewriteAction::RemoveBlock(0x200)];
        rw.apply_actions(&mut cfg, &actions);
        assert!(!cfg.blocks.contains_key(&0x200));
    }

    #[test]
    fn apply_actions_replace_block() {
        let mut cfg = simple_cfg();
        let rw = DispatcherRewriter::new();
        let new_insns = vec![0x90u8, 0x90];
        let actions = vec![RewriteAction::ReplaceBlock { addr: 0x100, new_insns: new_insns.clone() }];
        rw.apply_actions(&mut cfg, &actions);
        assert_eq!(cfg.blocks[&0x100].insns, new_insns);
    }

    #[test]
    fn merge_blocks() {
        let mut cfg = Cfg::new(0x100);
        let mut a = BasicBlock::new(0x100);
        a.insns = vec![0x01, 0x02];
        let mut b = BasicBlock::new(0x200);
        b.insns = vec![0x03, 0x04];
        b.predecessors = vec![0x100];
        cfg.add_block(a);
        cfg.add_block(b);
        cfg.add_edge(0x100, 0x200);
        let rw = DispatcherRewriter::new();
        let actions = vec![RewriteAction::MergeBlocks { a: 0x100, b: 0x200 }];
        rw.apply_actions(&mut cfg, &actions);
        assert_eq!(cfg.blocks[&0x100].insns, vec![0x01, 0x02, 0x03, 0x04]);
        assert!(!cfg.blocks.contains_key(&0x200));
    }

    #[test]
    fn validate_result_clean() {
        let mut cfg = Cfg::new(0x100);
        let entry = BasicBlock::new(0x100);
        cfg.add_block(entry);
        let rw = DispatcherRewriter::new();
        let errors = rw.validate_result(&cfg);
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_result_missing_entry() {
        let cfg = Cfg::new(0xDEAD);
        let rw = DispatcherRewriter::new();
        let errors = rw.validate_result(&cfg);
        assert!(!errors.is_empty());
    }

    #[test]
    fn validate_result_dangling_successor() {
        let mut cfg = Cfg::new(0x100);
        let mut entry = BasicBlock::new(0x100);
        entry.successors.push(0x999); // nonexistent
        cfg.add_block(entry);
        let rw = DispatcherRewriter::new();
        let errors = rw.validate_result(&cfg);
        assert!(!errors.is_empty());
    }

    #[test]
    fn validate_unreachable_block() {
        let mut cfg = Cfg::new(0x100);
        cfg.add_block(BasicBlock::new(0x100));
        cfg.add_block(BasicBlock::new(0x999)); // unreachable
        let rw = DispatcherRewriter::new();
        let errors = rw.validate_result(&cfg);
        assert!(errors.iter().any(|e| e.contains("unreachable")));
    }

    #[test]
    fn diff_snapshots_detects_removed_block() {
        let cfg_before = simple_cfg();
        let mut cfg_after = simple_cfg();
        cfg_after.blocks.remove(&0x200);
        let snap_before = CfgSnapshot::capture(&cfg_before);
        let snap_after = CfgSnapshot::capture(&cfg_after);
        let rw = DispatcherRewriter::new();
        let diff = rw.diff_snapshots(&snap_before, &snap_after);
        let has_remove = diff.actions.iter().any(|a| matches!(a, RewriteAction::RemoveBlock(0x200)));
        assert!(has_remove);
    }

    #[test]
    fn diff_snapshots_detects_added_edge() {
        let cfg_before = simple_cfg();
        let mut cfg_after = simple_cfg();
        cfg_after.add_edge(0x300, 0x400);
        let snap_before = CfgSnapshot::capture(&cfg_before);
        let snap_after  = CfgSnapshot::capture(&cfg_after);
        let rw = DispatcherRewriter::new();
        let diff = rw.diff_snapshots(&snap_before, &snap_after);
        assert!(diff.actions.iter().any(|a| matches!(a, RewriteAction::AddEdge(0x300, 0x400))));
    }

    #[test]
    fn inline_state_sequence_finds_chain() {
        let mut cfg = Cfg::new(0x100);
        cfg.add_block(BasicBlock::new(0x100));
        cfg.add_block(BasicBlock::new(0x200));
        cfg.add_block(BasicBlock::new(0x300));
        cfg.add_edge(0x100, 0x200);
        cfg.add_edge(0x200, 0x300);
        let rw = DispatcherRewriter::new();
        let res = rw.inline_state_sequence(&cfg);
        let has_merge = res.actions.iter().any(|a| matches!(a, RewriteAction::MergeBlocks { .. }));
        assert!(has_merge);
    }
}
