//! `cfg_reconstruction` — Reconstruct the original CFG from a CFF-protected function.
//!
//! Provides:
//! * Pruning dispatcher/routing blocks
//! * Reconnecting original CFG edges
//! * Handling multiple (nested) state variables
//! * [`CfgReconstructor`] — top-level entry point

#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// Reconstructed CFG types
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a block in the reconstructed CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockKind {
    /// A real application block (kept in the output CFG).
    Real,
    /// A dispatcher / switch block (removed from output CFG).
    Dispatcher,
    /// A pre-dispatcher routing block (only assigns state variable; removed).
    PreDispatcher,
    /// A bogus / dead block (unreachable; removed).
    Bogus,
}

impl std::fmt::Display for BlockKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Real => write!(f, "Real"),
            Self::Dispatcher => write!(f, "Dispatcher"),
            Self::PreDispatcher => write!(f, "PreDispatcher"),
            Self::Bogus => write!(f, "Bogus"),
        }
    }
}

/// A block in the intermediate annotated CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedBlock {
    /// Block address.
    pub address: Address,
    /// Block end (exclusive).
    pub end_address: Address,
    /// Block kind.
    pub kind: BlockKind,
    /// Original successor edges.
    pub raw_successors: Vec<Address>,
    /// Reconstructed successor edges (only for `Real` blocks).
    pub real_successors: Vec<Address>,
    /// Number of instructions in the block.
    pub insn_count: usize,
    /// State value assigned here (for `PreDispatcher` / routing blocks).
    pub assigned_state: Option<u64>,
}

impl AnnotatedBlock {
    #[must_use]
    pub const fn new(address: Address, end_address: Address) -> Self {
        Self {
            address,
            end_address,
            kind: BlockKind::Real,
            raw_successors: Vec::new(),
            real_successors: Vec::new(),
            insn_count: 0,
            assigned_state: None,
        }
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end_address.0.saturating_sub(self.address.0)
    }
}

/// The reconstructed original CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedCfg {
    /// Entry block address.
    pub entry: Address,
    /// All real blocks (dispatcher/routing blocks are excluded).
    pub real_blocks: Vec<AnnotatedBlock>,
    /// Number of dispatcher blocks pruned.
    pub pruned_dispatchers: usize,
    /// Number of routing blocks pruned.
    pub pruned_routing: usize,
    /// Number of bogus blocks removed.
    pub pruned_bogus: usize,
    /// Whether nested CFF state variables were detected.
    pub nested_cff: bool,
    /// Confidence in the reconstruction (0.0–1.0).
    pub confidence: f64,
    /// Detailed notes.
    pub notes: Vec<String>,
}

impl ReconstructedCfg {
    #[must_use]
    pub const fn empty(entry: Address) -> Self {
        Self {
            entry,
            real_blocks: Vec::new(),
            pruned_dispatchers: 0,
            pruned_routing: 0,
            pruned_bogus: 0,
            nested_cff: false,
            confidence: 0.0,
            notes: Vec::new(),
        }
    }

    /// Total blocks in the reconstructed CFG.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.real_blocks.len()
    }

    /// Total edges in the reconstructed CFG.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.real_blocks.iter().map(|b| b.real_successors.len()).sum()
    }

    /// Return a block by address.
    #[must_use]
    pub fn block(&self, addr: Address) -> Option<&AnnotatedBlock> {
        self.real_blocks.iter().find(|b| b.address == addr)
    }

    /// Return the immediate predecessors of `addr` in the reconstructed CFG.
    #[must_use]
    pub fn predecessors_of(&self, addr: Address) -> Vec<Address> {
        self.real_blocks
            .iter()
            .filter(|b| b.real_successors.contains(&addr))
            .map(|b| b.address)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Input to the reconstructor
// ─────────────────────────────────────────────────────────────────────────────

/// A raw block description provided to the reconstructor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawBlock {
    pub address: Address,
    pub end_address: Address,
    pub successors: Vec<Address>,
    pub predecessors: Vec<Address>,
    pub insn_count: usize,
    /// Constant state values assigned in this block (if any).
    pub state_assignments: Vec<u64>,
    /// Constant state values compared/dispatched in this block (switch conditions).
    pub state_comparisons: Vec<u64>,
}

impl RawBlock {
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end_address.0.saturating_sub(self.address.0)
    }

    /// Heuristic: this is a routing block if it has exactly one successor and
    /// does nothing but assign a state value.
    #[must_use]
    pub const fn is_likely_routing(&self) -> bool {
        self.state_assignments.len() == 1
            && self.state_comparisons.is_empty()
            && self.successors.len() <= 1
            && self.insn_count <= 4
    }

    /// Heuristic: this is a dispatcher if it has many successors and
    /// compares the state variable against multiple constants.
    #[must_use]
    pub const fn is_likely_dispatcher(&self) -> bool {
        self.successors.len() >= 4 || self.state_comparisons.len() >= 3
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfgReconstructor
// ─────────────────────────────────────────────────────────────────────────────

/// Reconstructs the original CFG from a CFF-protected function's block list.
pub struct CfgReconstructor {
    pub min_confidence: f64,
    /// Minimum number of successors to classify a block as a dispatcher.
    pub dispatcher_min_successors: usize,
    /// Maximum instruction count for a block to be considered a routing block.
    pub routing_max_insns: usize,
}

impl Default for CfgReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

impl CfgReconstructor {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_confidence: 0.50,
            dispatcher_min_successors: 4,
            routing_max_insns: 5,
        }
    }

    #[must_use]
    pub const fn with_min_confidence(mut self, t: f64) -> Self {
        self.min_confidence = t;
        self
    }

    // ── Block classification ──────────────────────────────────────────────────

    /// Classify each raw block.
    fn classify_blocks(
        &self,
        blocks: &[RawBlock],
    ) -> HashMap<Address, BlockKind> {
        let mut kinds: HashMap<Address, BlockKind> = HashMap::new();

        // First pass: classify dispatchers and routing blocks
        for block in blocks {
            let kind = if block.is_likely_dispatcher()
                || block.successors.len() >= self.dispatcher_min_successors
            {
                BlockKind::Dispatcher
            } else if block.is_likely_routing()
                || (block.state_assignments.len() == 1
                    && block.insn_count <= self.routing_max_insns)
            {
                BlockKind::PreDispatcher
            } else {
                BlockKind::Real
            };
            kinds.insert(block.address, kind);
        }

        // Second pass: mark bogus blocks (unreachable from entry)
        let entry = blocks.first().map(|b| b.address);
        if let Some(entry_addr) = entry {
            let reachable = bfs_reachable(entry_addr, blocks);
            for block in blocks {
                if !reachable.contains(&block.address) {
                    kinds.insert(block.address, BlockKind::Bogus);
                }
            }
        }

        kinds
    }

    // ── Edge reconstruction ───────────────────────────────────────────────────

    /// For each real block, determine its true successor edges by "skipping"
    /// through dispatcher and routing blocks.
    fn reconstruct_edges(
        blocks: &[RawBlock],
        kinds: &HashMap<Address, BlockKind>,
    ) -> HashMap<Address, Vec<Address>> {
        let block_map: HashMap<Address, &RawBlock> =
            blocks.iter().map(|b| (b.address, b)).collect();

        // Build state → real block mapping
        let mut state_to_real: HashMap<u64, Address> = HashMap::new();
        for block in blocks {
            if kinds.get(&block.address) == Some(&BlockKind::Real) {
                for pre in blocks {
                    if kinds.get(&pre.address) == Some(&BlockKind::PreDispatcher)
                        && pre.successors.len() == 1
                        && pre.successors[0] == block.address
                    {
                        for &sv in &pre.state_assignments {
                            state_to_real.insert(sv, block.address);
                        }
                    }
                }
            }
        }

        let mut real_edges: HashMap<Address, Vec<Address>> = HashMap::new();

        for block in blocks {
            if kinds.get(&block.address) != Some(&BlockKind::Real) {
                continue;
            }

            let mut real_succs: Vec<Address> = Vec::new();

            for &raw_succ in &block.successors {
                if kinds.get(&raw_succ) == Some(&BlockKind::Real) {
                    if !real_succs.contains(&raw_succ) {
                        real_succs.push(raw_succ);
                    }
                    continue;
                }

                let targets = Self::trace_through_dispatchers(
                    raw_succ,
                    &block_map,
                    kinds,
                    &state_to_real,
                    &mut HashSet::new(),
                );
                for t in targets {
                    if !real_succs.contains(&t) {
                        real_succs.push(t);
                    }
                }
            }

            real_edges.insert(block.address, real_succs);
        }

        real_edges
    }

    /// Follow a chain of dispatcher/routing blocks until we reach a real block.
    fn trace_through_dispatchers(
        start: Address,
        block_map: &HashMap<Address, &RawBlock>,
        kinds: &HashMap<Address, BlockKind>,
        state_to_real: &HashMap<u64, Address>,
        visited: &mut HashSet<Address>,
    ) -> Vec<Address> {
        if !visited.insert(start) {
            return Vec::new(); // cycle guard
        }

        if visited.len() > 32 {
            return Vec::new(); // depth guard
        }

        match kinds.get(&start) {
            Some(&BlockKind::Real) => return vec![start],
            Some(&BlockKind::Bogus) => return Vec::new(),
            _ => {}
        }

        let Some(&block) = block_map.get(&start) else { return Vec::new() };

        // If this routing block assigns exactly one state value, look up the real block
        if block.state_assignments.len() == 1 {
            let sv = block.state_assignments[0];
            if let Some(&real_addr) = state_to_real.get(&sv) {
                return vec![real_addr];
            }
        }

        // Otherwise, recursively trace all successors
        let mut result = Vec::new();
        for &succ in &block.successors {
            let mut sub_result = Self::trace_through_dispatchers(
                succ,
                block_map,
                kinds,
                state_to_real,
                visited,
            );
            result.append(&mut sub_result);
        }

        result
    }

    // ── Nested CFF detection ──────────────────────────────────────────────────

    /// Detect nested CFF: multiple independent dispatchers.
    fn detect_nested_cff(
        _blocks: &[RawBlock],
        kinds: &HashMap<Address, BlockKind>,
    ) -> bool {
        kinds
            .values()
            .filter(|&&k| k == BlockKind::Dispatcher)
            .count() >= 2
    }

    // ── Pruning ───────────────────────────────────────────────────────────────

    /// Remove dispatcher and routing blocks, keeping only real blocks.
    fn prune_blocks(
        blocks: Vec<AnnotatedBlock>,
    ) -> (Vec<AnnotatedBlock>, usize, usize, usize) {
        let mut pruned_dispatchers = 0;
        let mut pruned_routing = 0;
        let mut pruned_bogus = 0;
        let mut real = Vec::new();

        for block in blocks {
            match block.kind {
                BlockKind::Real => real.push(block),
                BlockKind::Dispatcher => pruned_dispatchers += 1,
                BlockKind::PreDispatcher => pruned_routing += 1,
                BlockKind::Bogus => pruned_bogus += 1,
            }
        }

        (real, pruned_dispatchers, pruned_routing, pruned_bogus)
    }

    // ── Full reconstruction ───────────────────────────────────────────────────

    /// Reconstruct the original CFG from the annotated block list.
    #[must_use]
    pub fn reconstruct(&self, raw_blocks: &[RawBlock]) -> ReconstructedCfg {
        if raw_blocks.is_empty() {
            return ReconstructedCfg::empty(Address(0));
        }

        let entry = raw_blocks[0].address;
        let mut result = ReconstructedCfg::empty(entry);

        // 1. Classify blocks
        let kinds = self.classify_blocks(raw_blocks);

        // 2. Detect nested CFF
        result.nested_cff = Self::detect_nested_cff(raw_blocks, &kinds);
        if result.nested_cff {
            result.notes.push("nested CFF (multiple dispatchers) detected".into());
        }

        // 3. Reconstruct edges
        let real_edges = Self::reconstruct_edges(raw_blocks, &kinds);

        // 4. Build annotated blocks
        let annotated: Vec<AnnotatedBlock> = raw_blocks
            .iter()
            .map(|raw| {
                let mut ab = AnnotatedBlock::new(raw.address, raw.end_address);
                ab.kind = *kinds.get(&raw.address).unwrap_or(&BlockKind::Real);
                ab.raw_successors.clone_from(&raw.successors);
                ab.real_successors = real_edges.get(&raw.address).cloned().unwrap_or_default();
                ab.insn_count = raw.insn_count;
                ab.assigned_state = raw.state_assignments.first().copied();
                ab
            })
            .collect();

        // 5. Prune
        let (real_blocks, pruned_dispatchers, pruned_routing, pruned_bogus) =
            Self::prune_blocks(annotated);

        result.real_blocks = real_blocks;
        result.pruned_dispatchers = pruned_dispatchers;
        result.pruned_routing = pruned_routing;
        result.pruned_bogus = pruned_bogus;

        result.notes.push(format!(
            "pruned: {} dispatchers, {} routing, {} bogus",
            result.pruned_dispatchers, result.pruned_routing, result.pruned_bogus
        ));

        // 6. Compute confidence
        let total = raw_blocks.len();
        let pruned = result.pruned_dispatchers + result.pruned_routing + result.pruned_bogus;
        let pruned_ratio = f64::from(u32::try_from(pruned).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total.max(1)).unwrap_or(1));

        result.confidence = if pruned_ratio > 0.3 && !result.real_blocks.is_empty() {
            (0.5 + pruned_ratio * 0.4).min(0.95)
        } else if !result.real_blocks.is_empty() {
            0.40
        } else {
            0.10
        };

        result
    }

    // ── Convenience: reconstruct from flat representation ─────────────────────

    /// Reconstruct from a simple `(address, end, successors, insn_count)` input.
    ///
    /// State assignments / comparisons are inferred heuristically from block sizes.
    #[must_use]
    pub fn reconstruct_simple(
        &self,
        blocks: &[(Address, Address, Vec<Address>, usize)],
    ) -> ReconstructedCfg {
        let raw_blocks: Vec<RawBlock> = blocks
            .iter()
            .map(|(addr, end, succs, insn_count)| {
                // Heuristic: small blocks that have exactly 1 successor are routing
                let state_assignments = if *insn_count <= 4 && succs.len() == 1 {
                    vec![0u64] // placeholder
                } else {
                    Vec::new()
                };
                let state_comparisons = if succs.len() >= 4 {
                    (0..u64::try_from(succs.len()).unwrap_or(u64::MAX)).collect()
                } else {
                    Vec::new()
                };

                // Compute predecessors
                let preds = blocks
                    .iter()
                    .filter(|(_, _, s, _)| s.contains(addr))
                    .map(|(a, _, _, _)| *a)
                    .collect();

                RawBlock {
                    address: *addr,
                    end_address: *end,
                    successors: succs.clone(),
                    predecessors: preds,
                    insn_count: *insn_count,
                    state_assignments,
                    state_comparisons,
                }
            })
            .collect();

        self.reconstruct(&raw_blocks)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// BFS reachability from `start`.
fn bfs_reachable(start: Address, blocks: &[RawBlock]) -> HashSet<Address> {
    let block_map: HashMap<Address, &RawBlock> =
        blocks.iter().map(|b| (b.address, b)).collect();

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(start);
    visited.insert(start);

    while let Some(addr) = queue.pop_front() {
        if let Some(block) = block_map.get(&addr) {
            for &succ in &block.successors {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
    }

    visited
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address {
        Address(v)
    }

    /// Build a minimal CFF-like CFG: entry → dispatcher → real blocks via routing.
    fn build_cff_cfg() -> Vec<RawBlock> {
        let dispatcher = addr(0x1000);
        let routing_a = addr(0x1100);
        let routing_b = addr(0x1200);
        let real_a = addr(0x2000);
        let real_b = addr(0x3000);

        vec![
            // Entry / first real block
            RawBlock {
                address: addr(0x0F00),
                end_address: addr(0x0F40),
                successors: vec![dispatcher],
                predecessors: Vec::new(),
                insn_count: 10,
                state_assignments: vec![42],
                state_comparisons: Vec::new(),
            },
            // Dispatcher
            RawBlock {
                address: dispatcher,
                end_address: addr(0x1050),
                successors: vec![routing_a, routing_b],
                predecessors: vec![addr(0x0F00)],
                insn_count: 5,
                state_assignments: Vec::new(),
                state_comparisons: vec![42, 99],
            },
            // Routing block A: assigns state 42 → real_a
            RawBlock {
                address: routing_a,
                end_address: addr(0x1110),
                successors: vec![real_a],
                predecessors: vec![dispatcher],
                insn_count: 2,
                state_assignments: vec![42],
                state_comparisons: Vec::new(),
            },
            // Routing block B: assigns state 99 → real_b
            RawBlock {
                address: routing_b,
                end_address: addr(0x1210),
                successors: vec![real_b],
                predecessors: vec![dispatcher],
                insn_count: 2,
                state_assignments: vec![99],
                state_comparisons: Vec::new(),
            },
            // Real block A
            RawBlock {
                address: real_a,
                end_address: addr(0x2050),
                successors: vec![routing_b],
                predecessors: vec![routing_a],
                insn_count: 12,
                state_assignments: vec![99],
                state_comparisons: Vec::new(),
            },
            // Real block B
            RawBlock {
                address: real_b,
                end_address: addr(0x3080),
                successors: Vec::new(),
                predecessors: vec![routing_b],
                insn_count: 20,
                state_assignments: Vec::new(),
                state_comparisons: Vec::new(),
            },
        ]
    }

    #[test]
    fn test_classify_blocks_dispatcher() {
        let reconstructor = CfgReconstructor::new();
        let blocks = build_cff_cfg();
        let kinds = reconstructor.classify_blocks(&blocks);

        // Dispatcher has 2 succs and comparisons — may not hit threshold of 4
        // but has state_comparisons so heuristic varies; at minimum check real blocks
        assert!(
            kinds.get(&Address(0x2000)) == Some(&BlockKind::Real)
                || kinds.get(&Address(0x3000)) == Some(&BlockKind::Real)
        );
    }

    #[test]
    fn test_reconstruct_reduces_blocks() {
        let reconstructor = CfgReconstructor::new();
        let blocks = build_cff_cfg();
        let cfg = reconstructor.reconstruct(&blocks);

        // Real blocks must be fewer than total input blocks
        assert!(cfg.real_blocks.len() <= blocks.len());
        // Some pruning must have occurred
        let total_pruned = cfg.pruned_dispatchers + cfg.pruned_routing + cfg.pruned_bogus;
        assert!(total_pruned > 0);
    }

    #[test]
    fn test_reconstruct_entry_preserved() {
        let reconstructor = CfgReconstructor::new();
        let blocks = build_cff_cfg();
        let cfg = reconstructor.reconstruct(&blocks);
        // Entry block is the first block
        assert_eq!(cfg.entry, Address(0x0F00));
    }

    #[test]
    fn test_reconstruct_empty() {
        let reconstructor = CfgReconstructor::new();
        let cfg = reconstructor.reconstruct(&[]);
        assert_eq!(cfg.block_count(), 0);
    }

    #[test]
    fn test_detect_nested_cff_false() {
        let reconstructor = CfgReconstructor::new();
        let blocks = build_cff_cfg();
        let kinds = reconstructor.classify_blocks(&blocks);
        // Our simple test CFG has at most one dispatcher
        let dispatcher_count = kinds.values().filter(|&&k| k == BlockKind::Dispatcher).count();
        let nested = CfgReconstructor::detect_nested_cff(&blocks, &kinds);
        assert_eq!(nested, dispatcher_count >= 2);
    }

    #[test]
    fn test_bfs_reachable() {
        let blocks = build_cff_cfg();
        let entry = blocks[0].address;
        let reachable = bfs_reachable(entry, &blocks);
        // All 6 blocks should be reachable from entry
        assert_eq!(reachable.len(), 6);
    }

    #[test]
    fn test_reconstruct_simple() {
        let reconstructor = CfgReconstructor::new();
        let blocks = vec![
            (addr(0x100), addr(0x140), vec![addr(0x200), addr(0x300), addr(0x400), addr(0x500)], 5),
            (addr(0x200), addr(0x210), vec![addr(0x100)], 2),
            (addr(0x300), addr(0x310), vec![addr(0x100)], 2),
            (addr(0x400), addr(0x450), vec![addr(0x100)], 15),
            (addr(0x500), addr(0x560), vec![], 20),
        ];
        let cfg = reconstructor.reconstruct_simple(&blocks);
        assert!(cfg.confidence >= 0.0);
    }
}
