//! Control flow graph diffing between two versions of a function.
//!
//! Detects added/removed basic blocks, changed edges, loop structure changes,
//! and dominance-tree mutations.

use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};

// ── Address type ─────────────────────────────────────────────────────────────

/// A virtual address used as a block identifier.
pub type Addr = u64;

// ── Basic block descriptor ────────────────────────────────────────────────────

/// Terminator kind for a basic block.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Terminator {
    /// Unconditional branch.
    Jump(Addr),
    /// Conditional branch with true/false targets.
    Branch { true_target: Addr, false_target: Addr },
    /// Indirect branch (switch / computed goto).
    IndirectJump { targets: Vec<Addr> },
    /// Function call that returns; `next` is the fall-through block.
    Call { callee: Option<Addr>, next: Addr },
    /// Return from function.
    Return,
    /// Unreachable / undefined.
    Unreachable,
}

impl Terminator {
    /// All successor addresses referenced by this terminator.
    #[must_use]
    pub fn successors(&self) -> Vec<Addr> {
        match self {
            Self::Jump(t) => vec![*t],
            Self::Branch { true_target, false_target } => {
                vec![*true_target, *false_target]
            }
            Self::IndirectJump { targets } => targets.clone(),
            Self::Call { next, .. } => vec![*next],
            Self::Return | Self::Unreachable => vec![],
        }
    }
}

/// A single basic block in a control flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Start address.
    pub addr: Addr,
    /// Byte length of the block.
    pub size: u32,
    /// Number of instructions contained.
    pub instruction_count: u32,
    /// How the block exits.
    pub terminator: Terminator,
    /// Optional human-readable label (e.g. from debug info).
    pub label: Option<String>,
}

impl BasicBlock {
    /// Create a new basic block.
    #[must_use]
    pub const fn new(addr: Addr, size: u32, instruction_count: u32, terminator: Terminator) -> Self {
        Self { addr, size, instruction_count, terminator, label: None }
    }

    /// Attach a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

// ── Control flow graph ────────────────────────────────────────────────────────

/// A control flow graph for one function version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    /// Function start address.
    pub entry: Addr,
    /// All basic blocks, keyed by start address.
    pub blocks: HashMap<Addr, BasicBlock>,
    /// Explicit edge list: (predecessor, successor).
    pub edges: Vec<(Addr, Addr)>,
}

impl ControlFlowGraph {
    /// Build a CFG from a list of basic blocks; edges are derived from terminators.
    #[must_use]
    pub fn from_blocks(entry: Addr, blocks: Vec<BasicBlock>) -> Self {
        let mut map: HashMap<Addr, BasicBlock> = HashMap::new();
        let mut edges: Vec<(Addr, Addr)> = Vec::new();

        for block in blocks {
            let addr = block.addr;
            for succ in block.terminator.successors() {
                edges.push((addr, succ));
            }
            map.insert(addr, block);
        }

        Self { entry, blocks: map, edges }
    }

    /// Return the set of all block addresses.
    #[must_use]
    pub fn block_addresses(&self) -> HashSet<Addr> {
        self.blocks.keys().copied().collect()
    }

    /// Successors of a block.
    #[must_use]
    pub fn successors(&self, addr: Addr) -> Vec<Addr> {
        self.edges.iter().filter(|(s, _)| *s == addr).map(|(_, t)| *t).collect()
    }

    /// Predecessors of a block.
    #[must_use]
    pub fn predecessors(&self, addr: Addr) -> Vec<Addr> {
        self.edges.iter().filter(|(_, t)| *t == addr).map(|(s, _)| *s).collect()
    }

    /// BFS-reachable block addresses starting from entry.
    #[must_use]
    pub fn reachable(&self) -> HashSet<Addr> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(self.entry);

        while let Some(addr) = queue.pop_front() {
            if visited.insert(addr) {
                for succ in self.successors(addr) {
                    if self.blocks.contains_key(&succ) && !visited.contains(&succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }
        visited
    }

    /// Compute dominators using the simple iterative algorithm (Cooper et al.).
    /// Returns a map from block → immediate dominator.
    #[must_use]
    pub fn compute_dominators(&self) -> HashMap<Addr, Addr> {
        // Cooper's algorithm walks up the dominator tree comparing
        // REVERSE-POSTORDER numbers, not addresses. Comparing addresses is not
        // merely imprecise: `idom[entry] == entry` makes the entry a fixed
        // point, so a join block with a predecessor at a lower address than the
        // entry — a cold block placed before the function start, which
        // compilers emit routinely — makes `intersect` spin forever.
        let rpo = self.reverse_postorder();
        let rpo_num: HashMap<Addr, usize> =
            rpo.iter().enumerate().map(|(i, &a)| (a, i)).collect();

        // Predecessors indexed once instead of rescanning every edge per block
        // per iteration.
        let mut preds_of: HashMap<Addr, Vec<Addr>> = HashMap::new();
        for &(s, t) in &self.edges {
            if rpo_num.contains_key(&s) && rpo_num.contains_key(&t) {
                preds_of.entry(t).or_default().push(s);
            }
        }

        let mut idom: HashMap<Addr, Addr> = HashMap::new();
        idom.insert(self.entry, self.entry);

        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter().skip(1) {
                let Some(preds) = preds_of.get(&b) else {
                    continue;
                };
                let mut new_idom: Option<Addr> = None;
                for &p in preds {
                    if !idom.contains_key(&p) {
                        continue;
                    }
                    new_idom = Some(match new_idom {
                        None => p,
                        Some(cur) => Self::intersect(&idom, &rpo_num, cur, p),
                    });
                }
                if let Some(new_idom) = new_idom
                    && idom.get(&b) != Some(&new_idom)
                {
                    idom.insert(b, new_idom);
                    changed = true;
                }
            }
        }
        idom
    }

    /// Blocks in reverse postorder starting at the entry (entry first).
    ///
    /// This is the order Cooper's dominator algorithm is defined over, and the
    /// only one for which its `intersect` is guaranteed to terminate.
    #[must_use]
    pub fn reverse_postorder(&self) -> Vec<Addr> {
        let mut succs_of: HashMap<Addr, Vec<Addr>> = HashMap::new();
        for &(s, t) in &self.edges {
            if self.blocks.contains_key(&t) {
                succs_of.entry(s).or_default().push(t);
            }
        }

        let mut postorder: Vec<Addr> = Vec::new();
        let mut visited: HashSet<Addr> = HashSet::new();
        // Iterative DFS: a deeply nested CFG must not blow the stack.
        let mut stack: Vec<(Addr, usize)> = vec![(self.entry, 0)];
        visited.insert(self.entry);
        while let Some((node, idx)) = stack.pop() {
            let empty: Vec<Addr> = Vec::new();
            let succs = succs_of.get(&node).unwrap_or(&empty);
            if idx < succs.len() {
                let next = succs[idx];
                stack.push((node, idx + 1));
                if visited.insert(next) {
                    stack.push((next, 0));
                }
            } else {
                postorder.push(node);
            }
        }
        postorder.reverse();
        postorder
    }

    fn intersect(
        idom: &HashMap<Addr, Addr>,
        rpo_num: &HashMap<Addr, usize>,
        mut b1: Addr,
        mut b2: Addr,
    ) -> Addr {
        let num = |a: Addr| rpo_num.get(&a).copied().unwrap_or(usize::MAX);
        while b1 != b2 {
            while num(b1) > num(b2) {
                match idom.get(&b1) {
                    // The entry is its own dominator: walking up from it can
                    // never make progress, so stop instead of spinning.
                    Some(&up) if up != b1 => b1 = up,
                    _ => return b2,
                }
            }
            while num(b2) > num(b1) {
                match idom.get(&b2) {
                    Some(&up) if up != b2 => b2 = up,
                    _ => return b1,
                }
            }
            if num(b1) == num(b2) && b1 != b2 {
                // Distinct blocks cannot share an RPO number; only unreachable
                // sentinels can. Bail rather than loop.
                return b1;
            }
        }
        b1
    }

    /// Detect back-edges (loops) in the CFG; returns (source, target) pairs.
    #[must_use]
    pub fn back_edges(&self) -> Vec<(Addr, Addr)> {
        let idom = self.compute_dominators();
        self.edges
            .iter()
            .filter(|(src, tgt)| {
                // A back-edge goes to a dominator of the source.
                let mut cur = *src;
                loop {
                    if cur == *tgt {
                        return true;
                    }
                    let parent = *idom.get(&cur).unwrap_or(&cur);
                    if parent == cur {
                        break;
                    }
                    cur = parent;
                }
                false
            })
            .copied()
            .collect()
    }
}

// ── Diff types ────────────────────────────────────────────────────────────────

/// How a basic block changed between two versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockChange {
    /// Block exists only in the old version.
    Removed,
    /// Block exists only in the new version.
    Added,
    /// Block exists in both but its content changed.
    Modified {
        /// Instruction count changed.
        instruction_count_delta: i32,
        /// Size in bytes changed.
        size_delta: i32,
        /// Terminator changed.
        terminator_changed: bool,
    },
    /// Block is identical in both versions.
    Unchanged,
}

/// A difference record for a single basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDiff {
    /// Block address (same in both versions for modified/unchanged blocks).
    pub addr: Addr,
    /// What changed.
    pub change: BlockChange,
    /// Block data from the old version (if it existed).
    pub old_block: Option<BasicBlock>,
    /// Block data from the new version (if it exists).
    pub new_block: Option<BasicBlock>,
}

/// A difference record for a single CFG edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeChange {
    /// Edge present only in the old CFG.
    Removed { from: Addr, to: Addr },
    /// Edge present only in the new CFG.
    Added { from: Addr, to: Addr },
}

/// How the loop structure changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopDiff {
    /// Back-edges present only in the old CFG.
    pub removed_back_edges: Vec<(Addr, Addr)>,
    /// Back-edges present only in the new CFG.
    pub added_back_edges: Vec<(Addr, Addr)>,
}

impl LoopDiff {
    /// True when no loop structure changed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.removed_back_edges.is_empty() && self.added_back_edges.is_empty()
    }
}

/// How the dominance tree changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DominanceDiff {
    /// Blocks whose immediate dominator changed.
    pub changed_idoms: Vec<IdomChange>,
}

/// A change to a block's immediate dominator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdomChange {
    pub block: Addr,
    pub old_idom: Addr,
    pub new_idom: Addr,
}

impl DominanceDiff {
    /// True when no dominance relationships changed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.changed_idoms.is_empty()
    }
}

/// Aggregate summary of a control flow diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgDiffSummary {
    pub blocks_added: usize,
    pub blocks_removed: usize,
    pub blocks_modified: usize,
    pub blocks_unchanged: usize,
    pub edges_added: usize,
    pub edges_removed: usize,
    pub loops_added: usize,
    pub loops_removed: usize,
}

/// Complete control flow diff between two function versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowDiff {
    /// Address of the function in the old binary (for reference).
    pub old_func_addr: Addr,
    /// Address of the function in the new binary (for reference).
    pub new_func_addr: Addr,
    /// Per-block differences.
    pub block_diffs: Vec<BlockDiff>,
    /// Per-edge differences.
    pub edge_changes: Vec<EdgeChange>,
    /// Loop (back-edge) differences.
    pub loop_diff: LoopDiff,
    /// Dominance tree differences.
    pub dominance_diff: DominanceDiff,
    /// Aggregate summary.
    pub summary: CfgDiffSummary,
}

impl ControlFlowDiff {
    /// Returns true if the two CFGs are identical.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.summary.blocks_added == 0
            && self.summary.blocks_removed == 0
            && self.summary.blocks_modified == 0
            && self.summary.edges_added == 0
            && self.summary.edges_removed == 0
    }

    /// A single-line human-readable description of the diff.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.is_identical() {
            return "CFG unchanged".to_string();
        }
        let mut parts = Vec::new();
        let s = &self.summary;
        if s.blocks_added > 0 {
            parts.push(format!("+{} blk", s.blocks_added));
        }
        if s.blocks_removed > 0 {
            parts.push(format!("-{} blk", s.blocks_removed));
        }
        if s.blocks_modified > 0 {
            parts.push(format!("~{} blk", s.blocks_modified));
        }
        if s.edges_added > 0 {
            parts.push(format!("+{} edge", s.edges_added));
        }
        if s.edges_removed > 0 {
            parts.push(format!("-{} edge", s.edges_removed));
        }
        if s.loops_added > 0 {
            parts.push(format!("+{} loop", s.loops_added));
        }
        if s.loops_removed > 0 {
            parts.push(format!("-{} loop", s.loops_removed));
        }
        parts.join(", ")
    }

    /// Filter block diffs to only the added blocks.
    #[must_use]
    pub fn added_blocks(&self) -> Vec<&BlockDiff> {
        self.block_diffs
            .iter()
            .filter(|d| d.change == BlockChange::Added)
            .collect()
    }

    /// Filter block diffs to only the removed blocks.
    #[must_use]
    pub fn removed_blocks(&self) -> Vec<&BlockDiff> {
        self.block_diffs
            .iter()
            .filter(|d| d.change == BlockChange::Removed)
            .collect()
    }

    /// Filter block diffs to only modified blocks.
    #[must_use]
    pub fn modified_blocks(&self) -> Vec<&BlockDiff> {
        self.block_diffs
            .iter()
            .filter(|d| matches!(d.change, BlockChange::Modified { .. }))
            .collect()
    }
}

// ── Address mapping ───────────────────────────────────────────────────────────

/// Strategy for aligning blocks between old and new CFGs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlignmentStrategy {
    /// Match blocks by exact address (assumes no rebasing).
    ExactAddress,
    /// Match blocks by their relative offset from the function entry.
    RelativeOffset,
    /// Match blocks using a provided address translation map.
    Mapped(HashMap<Addr, Addr>),
}

impl AlignmentStrategy {
    /// Translate an old-CFG address to a new-CFG address.
    #[must_use]
    pub fn translate(&self, old_addr: Addr, old_entry: Addr, new_entry: Addr) -> Addr {
        match self {
            Self::ExactAddress => old_addr,
            Self::RelativeOffset => {
                // The offset is SIGNED: cold and outlined blocks are placed
                // below the function entry, and `saturating_sub` clamped every
                // one of them to 0, aliasing them onto the new entry block.
                let offset = old_addr.wrapping_sub(old_entry) as i64;
                new_entry.wrapping_add_signed(offset)
            }
            Self::Mapped(map) => *map.get(&old_addr).unwrap_or(&old_addr),
        }
    }
}

// ── Differ ────────────────────────────────────────────────────────────────────

/// Computes a `ControlFlowDiff` between two CFGs.
#[derive(Debug)]
pub struct ControlFlowDiffer {
    strategy: AlignmentStrategy,
    /// Whether to compute dominance diff (slightly expensive).
    compute_dominance: bool,
}

impl Default for ControlFlowDiffer {
    fn default() -> Self {
        Self {
            strategy: AlignmentStrategy::ExactAddress,
            compute_dominance: true,
        }
    }
}

impl ControlFlowDiffer {
    /// Create a new differ with default settings (exact-address matching).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Use a specific alignment strategy.
    #[must_use]
    pub fn with_strategy(mut self, strategy: AlignmentStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Disable dominance diff computation.
    #[must_use]
    pub const fn without_dominance(mut self) -> Self {
        self.compute_dominance = false;
        self
    }

    fn compute_block_diffs(
        &self,
        old_cfg: &ControlFlowGraph,
        new_cfg: &ControlFlowGraph,
        translated_old: &HashMap<Addr, Addr>,
        translated_old_values: &HashSet<Addr>,
        new_addrs: &HashSet<Addr>,
    ) -> Vec<BlockDiff> {
        let mut block_diffs: Vec<BlockDiff> = Vec::new();
        for (&old_addr, &new_addr) in translated_old {
            if !new_addrs.contains(&new_addr) {
                block_diffs.push(BlockDiff {
                    addr: old_addr,
                    change: BlockChange::Removed,
                    old_block: old_cfg.blocks.get(&old_addr).cloned(),
                    new_block: None,
                });
            }
        }
        for &new_addr in new_addrs {
            if !translated_old_values.contains(&new_addr) {
                block_diffs.push(BlockDiff {
                    addr: new_addr,
                    change: BlockChange::Added,
                    old_block: None,
                    new_block: new_cfg.blocks.get(&new_addr).cloned(),
                });
            }
        }
        for (&old_addr, &translated_addr) in translated_old {
            if new_addrs.contains(&translated_addr) {
                let old_blk = &old_cfg.blocks[&old_addr];
                let new_blk = &new_cfg.blocks[&translated_addr];
                let term_changed = old_blk.terminator != new_blk.terminator;
                let ic_delta = i32::try_from(new_blk.instruction_count).unwrap_or(i32::MAX)
                    .wrapping_sub(i32::try_from(old_blk.instruction_count).unwrap_or(i32::MAX));
                let size_delta = i32::try_from(new_blk.size).unwrap_or(i32::MAX)
                    .wrapping_sub(i32::try_from(old_blk.size).unwrap_or(i32::MAX));
                let change = if ic_delta == 0 && size_delta == 0 && !term_changed {
                    BlockChange::Unchanged
                } else {
                    BlockChange::Modified { instruction_count_delta: ic_delta, size_delta, terminator_changed: term_changed }
                };
                block_diffs.push(BlockDiff {
                    addr: old_addr,
                    change,
                    old_block: Some(old_blk.clone()),
                    new_block: Some(new_blk.clone()),
                });
            }
        }
        block_diffs
    }

    fn compute_edge_diffs(
        &self,
        old_cfg: &ControlFlowGraph,
        new_cfg: &ControlFlowGraph,
        rev_translated: &HashMap<Addr, Addr>,
    ) -> Vec<EdgeChange> {
        let old_edge_set: HashSet<(Addr, Addr)> = old_cfg.edges.iter().map(|&(s, t)| {
            (self.strategy.translate(s, old_cfg.entry, new_cfg.entry),
             self.strategy.translate(t, old_cfg.entry, new_cfg.entry))
        }).collect();
        let new_edge_set: HashSet<(Addr, Addr)> = new_cfg.edges.iter().copied().collect();
        let mut edge_changes: Vec<EdgeChange> = Vec::new();
        for &(s, t) in &old_edge_set {
            if !new_edge_set.contains(&(s, t)) {
                let orig_s = *rev_translated.get(&s).unwrap_or(&s);
                let orig_t = *rev_translated.get(&t).unwrap_or(&t);
                edge_changes.push(EdgeChange::Removed { from: orig_s, to: orig_t });
            }
        }
        for &(s, t) in &new_edge_set {
            if !old_edge_set.contains(&(s, t)) {
                edge_changes.push(EdgeChange::Added { from: s, to: t });
            }
        }
        edge_changes
    }

    fn compute_loop_diff(&self, old_cfg: &ControlFlowGraph, new_cfg: &ControlFlowGraph) -> LoopDiff {
        let old_back: HashSet<(Addr, Addr)> = old_cfg.back_edges().into_iter().map(|(s, t)| {
            (self.strategy.translate(s, old_cfg.entry, new_cfg.entry),
             self.strategy.translate(t, old_cfg.entry, new_cfg.entry))
        }).collect();
        let new_back: HashSet<(Addr, Addr)> = new_cfg.back_edges().into_iter().collect();
        LoopDiff {
            removed_back_edges: old_back.difference(&new_back).copied().collect(),
            added_back_edges: new_back.difference(&old_back).copied().collect(),
        }
    }

    fn compute_dominance_diff(&self, old_cfg: &ControlFlowGraph, new_cfg: &ControlFlowGraph) -> DominanceDiff {
        if !self.compute_dominance {
            return DominanceDiff { changed_idoms: vec![] };
        }
        let old_idom = old_cfg.compute_dominators();
        let new_idom = new_cfg.compute_dominators();
        let mut changed_idoms = Vec::new();
        for (&old_addr, &old_idom_addr) in &old_idom {
            let new_addr = self.strategy.translate(old_addr, old_cfg.entry, new_cfg.entry);
            if let Some(&new_idom_addr) = new_idom.get(&new_addr) {
                let old_idom_t = self.strategy.translate(old_idom_addr, old_cfg.entry, new_cfg.entry);
                if old_idom_t != new_idom_addr {
                    changed_idoms.push(IdomChange { block: old_addr, old_idom: old_idom_addr, new_idom: new_idom_addr });
                }
            }
        }
        DominanceDiff { changed_idoms }
    }

    /// Diff two control flow graphs.
    ///
    /// `old_cfg` is from the original binary, `new_cfg` is from the patched binary.
    #[must_use]
    pub fn diff(&self, old_cfg: &ControlFlowGraph, new_cfg: &ControlFlowGraph) -> ControlFlowDiff {
        let old_addrs = old_cfg.block_addresses();
        let new_addrs = new_cfg.block_addresses();
        let translated_old: HashMap<Addr, Addr> = old_addrs.iter()
            .map(|&a| (a, self.strategy.translate(a, old_cfg.entry, new_cfg.entry)))
            .collect();
        let translated_old_values: HashSet<Addr> = translated_old.values().copied().collect();
        let rev_translated: HashMap<Addr, Addr> = translated_old.iter().map(|(&k, &v)| (v, k)).collect();

        let block_diffs = self.compute_block_diffs(old_cfg, new_cfg, &translated_old, &translated_old_values, &new_addrs);
        let edge_changes = self.compute_edge_diffs(old_cfg, new_cfg, &rev_translated);
        let loop_diff = self.compute_loop_diff(old_cfg, new_cfg);
        let dominance_diff = self.compute_dominance_diff(old_cfg, new_cfg);

        let summary = CfgDiffSummary {
            blocks_added: block_diffs.iter().filter(|d| d.change == BlockChange::Added).count(),
            blocks_removed: block_diffs.iter().filter(|d| d.change == BlockChange::Removed).count(),
            blocks_modified: block_diffs.iter().filter(|d| matches!(d.change, BlockChange::Modified { .. })).count(),
            blocks_unchanged: block_diffs.iter().filter(|d| d.change == BlockChange::Unchanged).count(),
            edges_added: edge_changes.iter().filter(|e| matches!(e, EdgeChange::Added { .. })).count(),
            edges_removed: edge_changes.iter().filter(|e| matches!(e, EdgeChange::Removed { .. })).count(),
            loops_added: loop_diff.added_back_edges.len(),
            loops_removed: loop_diff.removed_back_edges.len(),
        };

        ControlFlowDiff {
            old_func_addr: old_cfg.entry,
            new_func_addr: new_cfg.entry,
            block_diffs,
            edge_changes,
            loop_diff,
            dominance_diff,
            summary,
        }
    }
}

// ── Batch differ ──────────────────────────────────────────────────────────────

/// A matched function pair for batch diffing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCfgPair {
    /// Human-readable function name.
    pub name: String,
    pub old_cfg: ControlFlowGraph,
    pub new_cfg: ControlFlowGraph,
}

/// Results of a batch CFG diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCfgDiff {
    pub results: Vec<(String, ControlFlowDiff)>,
}

impl BatchCfgDiff {
    /// Number of unchanged functions.
    #[must_use]
    pub fn unchanged_count(&self) -> usize {
        self.results.iter().filter(|(_, d)| d.is_identical()).count()
    }

    /// Functions with changed CFGs.
    #[must_use]
    pub fn changed_functions(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter(|(_, d)| !d.is_identical())
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Functions where loops were added or removed.
    #[must_use]
    pub fn loop_changed_functions(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter(|(_, d)| !d.loop_diff.is_empty())
            .map(|(name, _)| name.as_str())
            .collect()
    }
}

/// Diff multiple function pairs in sequence.
#[must_use]
pub fn diff_batch(pairs: &[FunctionCfgPair], strategy: AlignmentStrategy) -> BatchCfgDiff {
    let differ = ControlFlowDiffer::new().with_strategy(strategy);
    let results = pairs
        .iter()
        .map(|pair| {
            let d = differ.diff(&pair.old_cfg, &pair.new_cfg);
            (pair.name.clone(), d)
        })
        .collect();
    BatchCfgDiff { results }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_linear_cfg(entry: Addr, n: u32) -> ControlFlowGraph {
        let mut blocks = Vec::new();
        for i in 0..n {
            let addr = entry + i as u64 * 16;
            let term = if i + 1 < n {
                Terminator::Jump(entry + (i + 1) as u64 * 16)
            } else {
                Terminator::Return
            };
            blocks.push(BasicBlock::new(addr, 16, 4, term));
        }
        ControlFlowGraph::from_blocks(entry, blocks)
    }

    #[test]
    fn test_identical_cfgs() {
        let cfg = make_linear_cfg(0x1000, 3);
        let differ = ControlFlowDiffer::new();
        let diff = differ.diff(&cfg, &cfg);
        assert!(diff.is_identical());
        assert_eq!(diff.summary.blocks_unchanged, 3);
    }

    #[test]
    fn test_added_block() {
        let old = make_linear_cfg(0x1000, 3);
        let new = make_linear_cfg(0x1000, 4);
        let differ = ControlFlowDiffer::new();
        let diff = differ.diff(&old, &new);
        assert_eq!(diff.summary.blocks_added, 1);
        assert!(!diff.is_identical());
    }

    #[test]
    fn test_removed_block() {
        let old = make_linear_cfg(0x1000, 4);
        let new = make_linear_cfg(0x1000, 3);
        let differ = ControlFlowDiffer::new();
        let diff = differ.diff(&old, &new);
        assert_eq!(diff.summary.blocks_removed, 1);
    }

    #[test]
    fn test_describe_non_empty() {
        let old = make_linear_cfg(0x1000, 4);
        let new = make_linear_cfg(0x1000, 3);
        let differ = ControlFlowDiffer::new();
        let diff = differ.diff(&old, &new);
        let desc = diff.describe();
        assert!(desc.contains("blk"), "desc = {desc}");
    }

    #[test]
    fn test_back_edge_detection() {
        // Build a simple loop: entry -> body -> entry (back edge), body -> exit
        let entry = 0x1000u64;
        let body = 0x1010u64;
        let exit = 0x1020u64;
        let blocks = vec![
            BasicBlock::new(entry, 16, 4, Terminator::Jump(body)),
            BasicBlock::new(
                body,
                16,
                4,
                Terminator::Branch { true_target: entry, false_target: exit },
            ),
            BasicBlock::new(exit, 16, 4, Terminator::Return),
        ];
        let cfg = ControlFlowGraph::from_blocks(entry, blocks);
        let back = cfg.back_edges();
        assert!(!back.is_empty(), "should detect back edge in loop");
        assert!(back.contains(&(body, entry)));
    }

    #[test]
    fn test_loop_diff_added() {
        // Old: linear; new: loop
        let old = make_linear_cfg(0x1000, 3);

        let entry = 0x1000u64;
        let mid = 0x1010u64;
        let fin = 0x1020u64;
        let new_blocks = vec![
            BasicBlock::new(entry, 16, 4, Terminator::Jump(mid)),
            BasicBlock::new(
                mid,
                16,
                4,
                Terminator::Branch { true_target: entry, false_target: fin },
            ),
            BasicBlock::new(fin, 16, 4, Terminator::Return),
        ];
        let new = ControlFlowGraph::from_blocks(entry, new_blocks);

        let differ = ControlFlowDiffer::new();
        let diff = differ.diff(&old, &new);
        assert_eq!(diff.summary.loops_added, 1);
    }

    #[test]
    fn test_batch_diff() {
        let old = make_linear_cfg(0x1000, 3);
        let new = make_linear_cfg(0x1000, 4);
        let pairs = vec![FunctionCfgPair {
            name: "test_fn".to_string(),
            old_cfg: old,
            new_cfg: new,
        }];
        let batch = diff_batch(&pairs, AlignmentStrategy::ExactAddress);
        assert_eq!(batch.results.len(), 1);
        assert_eq!(batch.changed_functions(), vec!["test_fn"]);
    }

    #[test]
    fn test_reachable_skips_unreachable_blocks() {
        let entry = 0x1000u64;
        let reachable = 0x1010u64;
        let unreachable = 0x9999u64;
        let blocks = vec![
            BasicBlock::new(entry, 16, 4, Terminator::Jump(reachable)),
            BasicBlock::new(reachable, 16, 4, Terminator::Return),
            BasicBlock::new(unreachable, 16, 4, Terminator::Return),
        ];
        let cfg = ControlFlowGraph::from_blocks(entry, blocks);
        let r = cfg.reachable();
        assert!(r.contains(&entry));
        assert!(r.contains(&reachable));
        assert!(!r.contains(&unreachable));
    }
}
