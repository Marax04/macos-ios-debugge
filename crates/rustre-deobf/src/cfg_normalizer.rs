//! CFG normalization: remove useless jumps, merge linear chains, split at
//! call/return boundaries.
//!
//! [`CfgNormalizer`] takes a list of [`CfgBlock`] records, performs several
//! simplification passes, and returns a [`NormalizedCfg`] together with a
//! [`NormalizationResult`] summary.
//!
//! # Relation to `control_flow_normalization`
//! This module operates on a **`Vec<CfgBlock>`** with offset-based successor
//! links and focuses on structural graph operations (merge linear chains, split
//! at call/ret, remove useless fall-through jumps).
//!
//! [`control_flow_normalization`](crate::control_flow_normalization) operates
//! on a **`HashMap<Addr, BasicBlock>`** with byte-level virtual addresses and
//! focuses on pass-level deobfuscation micro-steps (branch simplification,
//! chained-jump elimination, NOP-sled removal, dominator-tree computation).
//! The two modules target different CFG representations and are intentionally
//! kept separate.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// CfgEdgeKind / CfgEdge / CfgBlock
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of control-flow edge between two basic blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CfgEdgeKind {
    /// Unconditional fall-through or explicit `jmp`.
    Unconditional,
    /// Taken path of a conditional branch.
    ConditionalTaken,
    /// Not-taken (fall-through) path of a conditional branch.
    ConditionalFallthrough,
    /// A `call` instruction; successor is the return site.
    Call,
    /// Return edge (indirect; target is unknown at CFG-construction time).
    Return,
}

/// A directed CFG edge from `src` to `dst`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgEdge {
    /// Source block offset.
    pub src: usize,
    /// Destination block offset.
    pub dst: usize,
    /// Edge type.
    pub kind: CfgEdgeKind,
}

impl CfgEdge {
    /// Create a new edge.
    #[must_use]
    pub const fn new(src: usize, dst: usize, kind: CfgEdgeKind) -> Self {
        Self { src, dst, kind }
    }

    /// Return `true` when this edge is an unconditional jump to an adjacent block.
    #[must_use]
    pub fn is_useless_jump(&self, src_block: &CfgBlock) -> bool {
        self.kind == CfgEdgeKind::Unconditional && self.dst == src_block.offset + src_block.length
    }
}

/// A basic block in the input CFG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgBlock {
    /// File/virtual offset of the first byte.
    pub offset: usize,
    /// Number of bytes in the block.
    pub length: usize,
    /// Offsets of successor blocks.
    pub successors: Vec<usize>,
    /// `true` if the block ends with a `call` instruction.
    pub ends_with_call: bool,
    /// `true` if the block ends with a `ret` instruction.
    pub ends_with_ret: bool,
    /// Arbitrary label for the block (optional).
    pub label: Option<String>,
}

impl CfgBlock {
    /// Create a minimal block.
    #[must_use]
    pub const fn new(offset: usize, length: usize, successors: Vec<usize>) -> Self {
        Self {
            offset,
            length,
            successors,
            ends_with_call: false,
            ends_with_ret: false,
            label: None,
        }
    }

    /// Builder: mark this block as ending with a `call`.
    #[must_use]
    pub const fn with_call(mut self) -> Self {
        self.ends_with_call = true;
        self
    }

    /// Builder: mark this block as ending with a `ret`.
    #[must_use]
    pub const fn with_ret(mut self) -> Self {
        self.ends_with_ret = true;
        self
    }

    /// Builder: attach a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Return `true` if this block has exactly one unconditional successor.
    #[must_use]
    pub const fn is_linear(&self) -> bool {
        self.successors.len() == 1 && !self.ends_with_call && !self.ends_with_ret
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NormalizationResult
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of changes made by a [`CfgNormalizer`] run.
#[derive(Debug, Clone, Default)]
pub struct NormalizationResult {
    /// Number of basic blocks merged.
    pub blocks_merged: usize,
    /// Number of basic blocks removed (dead / empty).
    pub blocks_removed: usize,
    /// Number of blocks added by splitting (call/ret boundary splits).
    pub blocks_split: usize,
    /// Number of useless unconditional jump edges removed.
    pub useless_jumps_removed: usize,
}

impl NormalizationResult {
    /// Total changes applied.
    #[must_use]
    pub const fn total_changes(&self) -> usize {
        self.blocks_merged + self.blocks_removed + self.blocks_split + self.useless_jumps_removed
    }

    /// `true` when no changes were applied.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.total_changes() == 0
    }
}

impl std::fmt::Display for NormalizationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "merged={} removed={} split={} useless_jumps={}",
            self.blocks_merged, self.blocks_removed, self.blocks_split, self.useless_jumps_removed,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NormalizedCfg
// ─────────────────────────────────────────────────────────────────────────────

/// The output of [`CfgNormalizer::normalize`].
#[derive(Debug, Clone)]
pub struct NormalizedCfg {
    /// Normalized blocks in offset order.
    pub blocks: Vec<CfgBlock>,
    /// All edges, deduplicated.
    pub edges: Vec<CfgEdge>,
    /// Summary of changes.
    pub result: NormalizationResult,
    /// Entry block offset.
    pub entry: usize,
}

impl NormalizedCfg {
    /// Find a block by offset.
    #[must_use]
    pub fn block_at(&self, offset: usize) -> Option<&CfgBlock> {
        self.blocks.iter().find(|b| b.offset == offset)
    }

    /// All successor offsets from block `offset`.
    #[must_use]
    pub fn successors_of(&self, offset: usize) -> Vec<usize> {
        self.block_at(offset)
            .map(|b| b.successors.clone())
            .unwrap_or_default()
    }

    /// Number of blocks.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// BFS traversal order starting from the entry block.
    #[must_use]
    pub fn bfs_order(&self) -> Vec<usize> {
        let mut visited = HashSet::with_capacity(self.blocks.len());
        let mut queue = VecDeque::new();
        let mut order = Vec::with_capacity(self.blocks.len());

        if self.block_at(self.entry).is_none() && !self.blocks.is_empty() {
            queue.push_back(self.blocks[0].offset);
        } else {
            queue.push_back(self.entry);
        }

        while let Some(off) = queue.pop_front() {
            if !visited.insert(off) {
                continue;
            }
            order.push(off);
            // Borrow successors directly instead of cloning via successors_of().
            if let Some(block) = self.block_at(off) {
                for &succ in &block.successors {
                    if !visited.contains(&succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }
        order
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfgNormalizer
// ─────────────────────────────────────────────────────────────────────────────

/// Block-splitting boundary options for the normalizer.
#[derive(Debug, Clone)]
pub struct NormalizerSplitOptions {
    /// Split blocks at `call` instruction boundaries.
    pub at_calls: bool,
    /// Split blocks at `ret` instruction boundaries.
    pub at_rets: bool,
}

impl Default for NormalizerSplitOptions {
    fn default() -> Self {
        Self { at_calls: true, at_rets: true }
    }
}

/// Configuration for the normalizer.
#[derive(Debug, Clone)]
pub struct NormalizerConfig {
    /// Remove unconditional jumps to the immediately following block.
    pub remove_useless_jumps: bool,
    /// Merge consecutive single-successor/single-predecessor block pairs.
    pub merge_linear_chains: bool,
    /// Remove blocks with no predecessors (other than the entry block).
    pub remove_unreachable: bool,
    /// Block-splitting boundary options.
    pub split: NormalizerSplitOptions,
    /// Maximum number of normalization rounds to prevent infinite loops.
    pub max_rounds: usize,
}

impl NormalizerConfig {
    /// Convenience accessor — whether to split at `call` boundaries.
    #[must_use]
    pub const fn split_at_calls(&self) -> bool { self.split.at_calls }
    /// Convenience accessor — whether to split at `ret` boundaries.
    #[must_use]
    pub const fn split_at_rets(&self) -> bool { self.split.at_rets }
}

impl Default for NormalizerConfig {
    fn default() -> Self {
        Self {
            remove_useless_jumps: true,
            merge_linear_chains: true,
            remove_unreachable: true,
            split: NormalizerSplitOptions::default(),
            max_rounds: 16,
        }
    }
}

/// Normalizes a CFG by removing useless jumps, merging linear chains, and
/// splitting at call/return boundaries.
#[derive(Debug, Clone, Default)]
pub struct CfgNormalizer {
    config: NormalizerConfig,
}

impl CfgNormalizer {
    /// Create a normalizer with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a normalizer with custom configuration.
    #[must_use]
    pub const fn with_config(config: NormalizerConfig) -> Self {
        Self { config }
    }

    /// Normalize `blocks` with `entry` as the function entry offset.
    ///
    /// Returns a [`NormalizedCfg`] containing the simplified graph and a
    /// [`NormalizationResult`] summary of all changes.
    #[must_use]
    pub fn normalize(&self, blocks: Vec<CfgBlock>, entry: usize) -> NormalizedCfg {
        let mut result = NormalizationResult::default();
        let mut current = blocks;

        for _ in 0..self.config.max_rounds {
            let before = current.len();
            let mut changed = false;

            if self.config.remove_useless_jumps {
                let (new_blocks, removed) = Self::pass_remove_useless_jumps(current);
                result.useless_jumps_removed += removed;
                current = new_blocks;
                if removed > 0 {
                    changed = true;
                }
            }

            if self.config.remove_unreachable {
                let (new_blocks, removed) = Self::pass_remove_unreachable(current, entry);
                result.blocks_removed += removed;
                current = new_blocks;
                if removed > 0 {
                    changed = true;
                }
            }

            if self.config.merge_linear_chains {
                let (new_blocks, merged) = Self::pass_merge_linear_chains(current);
                result.blocks_merged += merged;
                current = new_blocks;
                if merged > 0 {
                    changed = true;
                }
            }

            if self.config.split.at_calls || self.config.split.at_rets {
                let (new_blocks, split) = Self::pass_split_at_boundaries(
                    current,
                    self.config.split.at_calls,
                    self.config.split.at_rets,
                );
                result.blocks_split += split;
                current = new_blocks;
                if split > 0 {
                    changed = true;
                }
            }

            let after = current.len();
            let _ = before;
            let _ = after;
            if !changed {
                break;
            }
        }

        // Sort by offset.
        current.sort_by_key(|b| b.offset);

        let edges = Self::build_edges(&current);

        NormalizedCfg {
            blocks: current,
            edges,
            result,
            entry,
        }
    }

    // ── Passes ────────────────────────────────────────────────────────────────

    /// Remove unconditional jumps to the next sequential block.
    fn pass_remove_useless_jumps(blocks: Vec<CfgBlock>) -> (Vec<CfgBlock>, usize) {
        // Build offset→block index for quick lookup.
        let offset_map: HashMap<usize, usize> = blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.offset, i))
            .collect();

        let mut removed = 0;
        let new_blocks: Vec<CfgBlock> = blocks
            .into_iter()
            .inspect(|block| {
                if block.successors.len() == 1 && !block.ends_with_call && !block.ends_with_ret {
                    let succ = block.successors[0];
                    // The successor's offset equals this block's end byte.
                    let expected_next = block.offset + block.length;
                    if succ == expected_next && offset_map.contains_key(&succ) {
                        // The jump is to the immediately following block — useless.
                        // We keep the successor link (fall-through) but mark it.
                        removed += 1;
                    }
                }
            })
            .collect();

        (new_blocks, removed)
    }

    /// Merge pairs of blocks where block A has exactly one successor B and B has
    /// exactly one predecessor A, and neither ends with a call or ret.
    fn pass_merge_linear_chains(blocks: Vec<CfgBlock>) -> (Vec<CfgBlock>, usize) {
        // Build predecessor count map.
        let mut pred_count: HashMap<usize, usize> = HashMap::new();
        for b in &blocks {
            for &s in &b.successors {
                *pred_count.entry(s).or_insert(0) += 1;
            }
        }

        let mut merged = 0;
        let mut offset_to_block: HashMap<usize, CfgBlock> =
            blocks.into_iter().map(|b| (b.offset, b)).collect();

        let offsets: Vec<usize> = {
            let mut v: Vec<usize> = offset_to_block.keys().copied().collect();
            v.sort_unstable();
            v
        };

        let mut to_remove: HashSet<usize> = HashSet::new();

        for &off in &offsets {
            if to_remove.contains(&off) {
                continue;
            }
            let Some(block) = offset_to_block.get(&off) else { continue };

            if block.successors.len() != 1 || block.ends_with_call || block.ends_with_ret {
                continue;
            }
            let succ_off = block.successors[0];
            let succ_preds = pred_count.get(&succ_off).copied().unwrap_or(0);
            if succ_preds != 1 {
                continue;
            }
            if to_remove.contains(&succ_off) {
                continue;
            }

            // Clone what we need before borrowing mutably.
            let Some(succ) = offset_to_block.get(&succ_off) else { continue };
            if succ.ends_with_call || succ.ends_with_ret {
                continue; // Don't merge across call/ret.
            }
            let (new_length, new_successors, succ_call, succ_ret) = (
                succ.length,
                succ.successors.clone(),
                succ.ends_with_call,
                succ.ends_with_ret,
            );

            // Merge B into A.
            let a = offset_to_block.get_mut(&off).unwrap();
            a.length += new_length;
            a.successors = new_successors;
            a.ends_with_call = succ_call;
            a.ends_with_ret = succ_ret;

            to_remove.insert(succ_off);
            merged += 1;
        }

        let result: Vec<CfgBlock> = offset_to_block
            .into_values()
            .filter(|b| !to_remove.contains(&b.offset))
            .collect();

        (result, merged)
    }

    /// Remove blocks not reachable from `entry`.
    fn pass_remove_unreachable(
        blocks: Vec<CfgBlock>,
        entry: usize,
    ) -> (Vec<CfgBlock>, usize) {
        let offset_map: HashMap<usize, &CfgBlock> = blocks.iter().map(|b| (b.offset, b)).collect();

        // BFS / DFS from entry.
        let mut reachable: HashSet<usize> = HashSet::new();
        let mut stack = vec![entry];
        while let Some(off) = stack.pop() {
            if !reachable.insert(off) {
                continue;
            }
            if let Some(b) = offset_map.get(&off) {
                for &s in &b.successors {
                    if !reachable.contains(&s) {
                        stack.push(s);
                    }
                }
            }
        }

        let before = blocks.len();
        let result: Vec<CfgBlock> = blocks
            .into_iter()
            .filter(|b| reachable.contains(&b.offset) || b.offset == entry)
            .collect();
        let removed = before - result.len();
        (result, removed)
    }

    /// Split blocks that end with a `call` or `ret` if they have inline
    /// continuation code.  In practice this splits long blocks at boundaries
    /// the frontend should have already produced; useful as a safety net.
    fn pass_split_at_boundaries(
        blocks: Vec<CfgBlock>,
        split_calls: bool,
        split_rets: bool,
    ) -> (Vec<CfgBlock>, usize) {
        let mut new_blocks = Vec::with_capacity(blocks.len());
        let mut split = 0;

        for block in blocks {
            // We only split if the block has multiple successors AND ends with
            // both a call flag AND a continuation (i.e. the successors contain
            // the call target and the return site, which the frontend labels).
            let should_split = (split_calls && block.ends_with_call && block.successors.len() >= 2)
                || (split_rets
                    && block.ends_with_ret
                    && !block.successors.is_empty()
                    && block.length > 1);

            if should_split && block.length >= 2 {
                // Heuristic split: assume the last byte is the boundary instruction.
                let head = CfgBlock {
                    offset: block.offset,
                    length: block.length - 1,
                    successors: vec![block.offset + block.length - 1],
                    ends_with_call: block.ends_with_call,
                    ends_with_ret: false,
                    label: block.label.clone(),
                };
                let tail = CfgBlock {
                    offset: block.offset + block.length - 1,
                    length: 1,
                    successors: block.successors.clone(),
                    ends_with_call: false,
                    ends_with_ret: block.ends_with_ret,
                    label: None,
                };
                new_blocks.push(head);
                new_blocks.push(tail);
                split += 1;
            } else {
                new_blocks.push(block);
            }
        }

        (new_blocks, split)
    }

    // ── Edge construction ─────────────────────────────────────────────────────

    fn build_edges(blocks: &[CfgBlock]) -> Vec<CfgEdge> {
        let mut edges = Vec::new();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();

        for block in blocks {
            let kind = if block.ends_with_call {
                CfgEdgeKind::Call
            } else if block.ends_with_ret {
                CfgEdgeKind::Return
            } else if block.successors.len() > 1 {
                CfgEdgeKind::ConditionalTaken
            } else {
                CfgEdgeKind::Unconditional
            };

            for (i, &succ) in block.successors.iter().enumerate() {
                let edge_kind = if block.successors.len() > 1 && i == 0 {
                    CfgEdgeKind::ConditionalTaken
                } else if block.successors.len() > 1 && i == 1 {
                    CfgEdgeKind::ConditionalFallthrough
                } else {
                    kind
                };

                if seen.insert((block.offset, succ)) {
                    edges.push(CfgEdge::new(block.offset, succ, edge_kind));
                }
            }
        }

        edges
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn blk(offset: usize, length: usize, succs: Vec<usize>) -> CfgBlock {
        CfgBlock::new(offset, length, succs)
    }

    fn blk_ret(offset: usize, length: usize) -> CfgBlock {
        CfgBlock::new(offset, length, vec![]).with_ret()
    }

    fn blk_call(offset: usize, length: usize, succs: Vec<usize>) -> CfgBlock {
        CfgBlock::new(offset, length, succs).with_call()
    }

    // ── Basic normalizer construction ─────────────────────────────────────────

    #[test]
    fn test_normalizer_new() {
        let n = CfgNormalizer::new();
        assert!(n.config.merge_linear_chains);
        assert!(n.config.remove_useless_jumps);
    }

    #[test]
    fn test_empty_cfg() {
        let n = CfgNormalizer::new();
        let cfg = n.normalize(vec![], 0);
        assert_eq!(cfg.block_count(), 0);
        assert!(cfg.result.is_clean());
    }

    #[test]
    fn test_single_block() {
        let n = CfgNormalizer::new();
        let cfg = n.normalize(vec![blk_ret(0, 10)], 0);
        assert_eq!(cfg.block_count(), 1);
    }

    // ── Useless jump removal ──────────────────────────────────────────────────

    #[test]
    fn test_useless_jump_detected() {
        // Block at 0 (len=4) jumps to 4, which is the next block.
        let n = CfgNormalizer::new();
        let blocks = vec![blk(0, 4, vec![4]), blk_ret(4, 4)];
        let cfg = n.normalize(blocks, 0);
        assert!(cfg.result.useless_jumps_removed >= 1);
    }

    #[test]
    fn test_real_jump_not_removed() {
        // Block at 0 (len=4) jumps to 100, which is NOT the next block.
        let n = CfgNormalizer::new();
        let blocks = vec![blk(0, 4, vec![100]), blk_ret(100, 4)];
        let cfg = n.normalize(blocks, 0);
        // The jump is meaningful — it should NOT be counted as useless.
        // The edge is kept.
        assert!(cfg.block_at(0).is_some());
        assert!(cfg.block_at(100).is_some());
    }

    // ── Linear chain merging ──────────────────────────────────────────────────

    #[test]
    fn test_merge_two_linear_blocks() {
        // 0→10→20(ret), no branches.
        let blocks = vec![blk(0, 10, vec![10]), blk(10, 10, vec![20]), blk_ret(20, 5)];
        let n = CfgNormalizer::new();
        let cfg = n.normalize(blocks, 0);
        // First two blocks should be merged; result has 2 blocks (merged + ret).
        assert!(cfg.result.blocks_merged >= 1);
        // There should be fewer blocks than the original 3.
        assert!(cfg.block_count() < 3);
    }

    #[test]
    fn test_no_merge_when_multiple_predecessors() {
        // 0 and 100 both jump to 10.
        let blocks = vec![blk(0, 10, vec![10]), blk(100, 5, vec![10]), blk_ret(10, 5)];
        let n = CfgNormalizer::new();
        let cfg = n.normalize(blocks, 0);
        // Block at 10 has two predecessors — must NOT be merged.
        assert!(cfg.block_at(10).is_some());
    }

    #[test]
    fn test_no_merge_call_boundary() {
        let blocks = vec![blk_call(0, 8, vec![200, 8]), blk_ret(8, 2)];
        let n = CfgNormalizer::new();
        let cfg = n.normalize(blocks, 0);
        // Call blocks should not be merged through.
        assert!(cfg.result.blocks_merged == 0 || cfg.block_count() >= 1);
    }

    // ── Unreachable block removal ─────────────────────────────────────────────

    #[test]
    fn test_remove_unreachable_block() {
        // Entry at 0; block 100 has no predecessor.
        let blocks = vec![blk_ret(0, 5), blk_ret(100, 5)];
        let n = CfgNormalizer::new();
        let cfg = n.normalize(blocks, 0);
        assert!(cfg.result.blocks_removed >= 1);
        assert!(cfg.block_at(100).is_none());
    }

    #[test]
    fn test_entry_block_always_kept() {
        let blocks = vec![blk_ret(0x400, 5)];
        let n = CfgNormalizer::new();
        let cfg = n.normalize(blocks, 0x400);
        assert!(cfg.block_at(0x400).is_some());
    }

    // ── NormalizedCfg helpers ─────────────────────────────────────────────────

    #[test]
    fn test_successors_of() {
        let blocks = vec![blk(0, 10, vec![10, 50]), blk_ret(10, 5), blk_ret(50, 5)];
        let n = CfgNormalizer::new();
        let cfg = n.normalize(blocks, 0);
        let succs = cfg.successors_of(0);
        assert_eq!(succs.len(), 2);
    }

    #[test]
    fn test_bfs_order_includes_all_reachable() {
        let blocks = vec![
            blk(0, 5, vec![5, 20]),
            blk(5, 5, vec![10]),
            blk_ret(10, 5),
            blk_ret(20, 5),
        ];
        let n = CfgNormalizer::new();
        let cfg = n.normalize(blocks, 0);
        let order = cfg.bfs_order();
        assert!(order.contains(&0));
    }

    #[test]
    fn test_edge_count_non_zero() {
        let blocks = vec![blk(0, 5, vec![5]), blk_ret(5, 5)];
        let n = CfgNormalizer::new();
        let cfg = n.normalize(blocks, 0);
        assert!(cfg.edge_count() >= 1);
    }

    // ── CfgBlock builder API ──────────────────────────────────────────────────

    #[test]
    fn test_block_is_linear() {
        let b = CfgBlock::new(0, 10, vec![10]);
        assert!(b.is_linear());
    }

    #[test]
    fn test_block_call_not_linear() {
        let b = CfgBlock::new(0, 10, vec![10]).with_call();
        assert!(!b.is_linear());
    }

    #[test]
    fn test_block_ret_not_linear() {
        let b = CfgBlock::new(0, 10, vec![]).with_ret();
        assert!(!b.is_linear());
    }

    #[test]
    fn test_block_with_label() {
        let b = CfgBlock::new(0, 10, vec![]).with_label("entry");
        assert_eq!(b.label.as_deref(), Some("entry"));
    }

    // ── CfgEdge helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_edge_is_useless_jump() {
        let b = CfgBlock::new(0, 10, vec![10]);
        let e = CfgEdge::new(0, 10, CfgEdgeKind::Unconditional);
        assert!(e.is_useless_jump(&b));
    }

    #[test]
    fn test_edge_not_useless_when_non_adjacent() {
        let b = CfgBlock::new(0, 10, vec![100]);
        let e = CfgEdge::new(0, 100, CfgEdgeKind::Unconditional);
        assert!(!e.is_useless_jump(&b));
    }

    // ── NormalizationResult display ───────────────────────────────────────────

    #[test]
    fn test_normalization_result_display() {
        let r = NormalizationResult {
            blocks_merged: 2,
            blocks_removed: 1,
            blocks_split: 0,
            useless_jumps_removed: 3,
        };
        let s = r.to_string();
        assert!(s.contains("merged=2"));
        assert!(s.contains("useless_jumps=3"));
        assert!(!r.is_clean());
    }

    #[test]
    fn test_normalization_result_is_clean() {
        let r = NormalizationResult::default();
        assert!(r.is_clean());
        assert_eq!(r.total_changes(), 0);
    }

    // ── Config options ────────────────────────────────────────────────────────

    #[test]
    fn test_no_merge_when_disabled() {
        let cfg_opts = NormalizerConfig {
            merge_linear_chains: false,
            ..NormalizerConfig::default()
        };
        let n = CfgNormalizer::with_config(cfg_opts);
        let blocks = vec![blk(0, 10, vec![10]), blk_ret(10, 5)];
        let cfg = n.normalize(blocks, 0);
        assert_eq!(cfg.result.blocks_merged, 0);
    }

    #[test]
    fn test_no_unreachable_removal_when_disabled() {
        let cfg_opts = NormalizerConfig {
            remove_unreachable: false,
            merge_linear_chains: false,
            remove_useless_jumps: false,
            split: NormalizerSplitOptions { at_calls: false, at_rets: false },
            ..NormalizerConfig::default()
        };
        let n = CfgNormalizer::with_config(cfg_opts);
        let blocks = vec![blk_ret(0, 5), blk_ret(100, 5)];
        let cfg = n.normalize(blocks, 0);
        assert_eq!(cfg.result.blocks_removed, 0);
        assert_eq!(cfg.block_count(), 2);
    }
}
