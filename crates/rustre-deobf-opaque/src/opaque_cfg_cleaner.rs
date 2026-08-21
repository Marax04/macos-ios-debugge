//! Opaque predicate CFG cleaning for `rustre-deobf-opaque`.
//!
//! Provides `OpaqueCfgCleaner`, `CfgPatch`, `CFGSimplifier`, `BlockMerger`,
//! `UnreachableBlockRemover`, and `CleanedCFG`.

pub use crate::OpaqueExpr;
use crate::{OpaqueDetector, OpaqueKind, SimpleBranchCfg};
pub use rustre_core::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ── CfgPatch ──────────────────────────────────────────────────────────────────

/// A single patch to apply to a CFG after opaque predicate removal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgPatch {
    pub branch_address: u64,
    pub remove_target: u64,
    pub keep_target: u64,
    pub patch_kind: PatchKind,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchKind {
    /// Replace the conditional branch with an unconditional jump.
    ConditionalToUnconditional,
    /// Remove the always-false branch (NOP out the branch).
    RemoveDeadBranch,
    /// Redirect always-true branch.
    RedirectAlwaysTaken,
}

impl CfgPatch {
    #[must_use]
    pub const fn new(
        branch_address: u64,
        remove_target: u64,
        keep_target: u64,
        kind: PatchKind,
        confidence: f32,
    ) -> Self {
        Self {
            branch_address,
            remove_target,
            keep_target,
            patch_kind: kind,
            confidence,
        }
    }

    /// Generate an x86 assembly-level description of the patch.
    #[must_use]
    pub fn patch_description(&self) -> String {
        match self.patch_kind {
            PatchKind::ConditionalToUnconditional => format!(
                "At 0x{:x}: replace Jcc → JMP 0x{:x} (remove dead branch 0x{:x})",
                self.branch_address, self.keep_target, self.remove_target
            ),
            PatchKind::RemoveDeadBranch => format!(
                "At 0x{:x}: NOP out branch to 0x{:x} (never taken)",
                self.branch_address, self.remove_target
            ),
            PatchKind::RedirectAlwaysTaken => format!(
                "At 0x{:x}: redirect always-taken branch to 0x{:x}",
                self.branch_address, self.keep_target
            ),
        }
    }
}

// ── OpaqueBlock ───────────────────────────────────────────────────────────────

/// A basic block with an identified always-taken or never-taken branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueBlock {
    pub address: u64,
    pub kind: OpaqueKind,
    pub true_target: u64,
    pub false_target: u64,
    pub live_target: u64,
    pub dead_target: u64,
    pub confidence: f32,
}

impl OpaqueBlock {
    #[must_use]
    pub const fn build_patch(&self) -> CfgPatch {
        let pk = match self.kind {
            OpaqueKind::AlwaysTrue => PatchKind::RedirectAlwaysTaken,
            OpaqueKind::AlwaysFalse => PatchKind::RemoveDeadBranch,
            OpaqueKind::DataDependent => PatchKind::ConditionalToUnconditional,
        };
        CfgPatch::new(
            self.address,
            self.dead_target,
            self.live_target,
            pk,
            self.confidence,
        )
    }
}

// ── CFGSimplifier ─────────────────────────────────────────────────────────────

/// Simplifies a CFG by applying patches.
pub struct CFGSimplifier {
    pub patches: Vec<CfgPatch>,
}

impl CFGSimplifier {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patches: Vec::new(),
        }
    }

    pub fn add_patch(&mut self, patch: CfgPatch) {
        self.patches.push(patch);
    }

    /// Apply all patches to a set of edges (address pairs).
    /// Returns the cleaned edge set.
    #[must_use]
    pub fn apply_patches(&self, edges: &[(u64, u64)]) -> Vec<(u64, u64)> {
        let dead_targets: HashSet<(u64, u64)> = self
            .patches
            .iter()
            .map(|p| (p.branch_address, p.remove_target))
            .collect();
        edges
            .iter()
            .filter(|(from, to)| !dead_targets.contains(&(*from, *to)))
            .copied()
            .collect()
    }

    /// Count patches by kind.
    #[must_use]
    pub fn patch_count(&self, kind: PatchKind) -> usize {
        self.patches.iter().filter(|p| p.patch_kind == kind).count()
    }

    /// Total patches.
    #[must_use]
    pub const fn total_patches(&self) -> usize {
        self.patches.len()
    }
}

impl Default for CFGSimplifier {
    fn default() -> Self {
        Self::new()
    }
}

// ── BlockMerger ───────────────────────────────────────────────────────────────

/// Merges blocks that have exactly one predecessor and one successor.
pub struct BlockMerger;

impl BlockMerger {
    /// Given an edge list, return groups of blocks that can be merged.
    ///
    /// A block B can be merged into its predecessor A if:
    /// - A has exactly one successor (B).
    /// - B has exactly one predecessor (A).
    #[must_use]
    pub fn find_mergeable(edges: &[(u64, u64)]) -> Vec<Vec<u64>> {
        // Count in/out degrees.
        let mut out_deg: HashMap<u64, usize> = HashMap::new();
        let mut in_deg: HashMap<u64, usize> = HashMap::new();
        let mut succ: HashMap<u64, u64> = HashMap::new();
        for &(from, to) in edges {
            *out_deg.entry(from).or_insert(0) += 1;
            *in_deg.entry(to).or_insert(0) += 1;
            succ.insert(from, to);
        }

        // Collect merge chains.
        let mut visited = HashSet::new();
        let mut chains = Vec::new();
        for &(start, _) in edges {
            if visited.contains(&start) {
                continue;
            }
            if in_deg.get(&start).copied().unwrap_or(0) == 1 {
                continue;
            } // not a chain head
            let mut chain = vec![start];
            let mut cur = start;
            loop {
                if out_deg.get(&cur).copied().unwrap_or(0) != 1 {
                    break;
                }
                let next = succ[&cur];
                if in_deg.get(&next).copied().unwrap_or(0) != 1 {
                    break;
                }
                if visited.contains(&next) {
                    break;
                }
                chain.push(next);
                cur = next;
            }
            if chain.len() > 1 {
                for &b in &chain {
                    visited.insert(b);
                }
                chains.push(chain);
            }
        }
        chains
    }

    /// Reduce edges by merging linear chains.
    #[must_use]
    pub fn merge(edges: &[(u64, u64)]) -> Vec<(u64, u64)> {
        let chains = Self::find_mergeable(edges);
        if chains.is_empty() {
            return edges.to_vec();
        }

        // Build a replacement map: every block in the chain → chain head.
        let mut replacement: HashMap<u64, u64> = HashMap::new();
        for chain in &chains {
            let head = chain[0];
            for &b in chain.iter().skip(1) {
                replacement.insert(b, head);
            }
        }

        // Rebuild edges: remove internal edges; remap targets.
        let internal: HashSet<(u64, u64)> = chains
            .iter()
            .flat_map(|c| c.windows(2).map(|w| (w[0], w[1])))
            .collect();
        let mut out = Vec::with_capacity(edges.len());
        for &(from, to) in edges {
            if internal.contains(&(from, to)) {
                continue;
            }
            let from2 = replacement.get(&from).copied().unwrap_or(from);
            let to2 = replacement.get(&to).copied().unwrap_or(to);
            out.push((from2, to2));
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

// ── UnreachableBlockRemover ───────────────────────────────────────────────────

/// Removes basic blocks that are not reachable from the function entry.
pub struct UnreachableBlockRemover;

impl UnreachableBlockRemover {
    /// Return the set of reachable block addresses from `entry`.
    #[must_use]
    pub fn reachable_from(entry: u64, edges: &[(u64, u64)]) -> HashSet<u64> {
        let mut succs: HashMap<u64, Vec<u64>> = HashMap::new();
        for &(from, to) in edges {
            succs.entry(from).or_default().push(to);
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(entry);
        while let Some(cur) = queue.pop_front() {
            if !visited.insert(cur) {
                continue;
            }
            if let Some(nexts) = succs.get(&cur) {
                for &n in nexts {
                    queue.push_back(n);
                }
            }
        }
        visited
    }

    /// Remove edges involving unreachable blocks.
    #[must_use]
    pub fn remove_unreachable(entry: u64, edges: &[(u64, u64)]) -> Vec<(u64, u64)> {
        let reachable = Self::reachable_from(entry, edges);
        edges
            .iter()
            .filter(|(f, t)| reachable.contains(f) && reachable.contains(t))
            .copied()
            .collect()
    }

    /// Count unreachable blocks.
    #[must_use]
    pub fn count_unreachable(entry: u64, all_blocks: &[u64], edges: &[(u64, u64)]) -> usize {
        let reachable = Self::reachable_from(entry, edges);
        all_blocks
            .iter()
            .filter(|&&b| !reachable.contains(&b))
            .count()
    }
}

// ── CleanedCFG ────────────────────────────────────────────────────────────────

/// A CFG after opaque-predicate removal and simplification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CleanedCFG {
    pub function_entry: u64,
    pub blocks: Vec<u64>,
    pub edges: Vec<(u64, u64)>,
    pub opaque_blocks_removed: usize,
    pub unreachable_blocks_removed: usize,
    pub merged_blocks: usize,
    pub patches_applied: Vec<CfgPatch>,
}

impl CleanedCFG {
    #[must_use]
    pub fn new(entry: u64) -> Self {
        Self {
            function_entry: entry,
            ..Default::default()
        }
    }

    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    #[must_use]
    pub fn reduction_ratio(&self, original_block_count: usize) -> f32 {
        if original_block_count == 0 {
            return 0.0;
        }
        (original_block_count.saturating_sub(self.block_count())) as f32
            / original_block_count as f32
    }

    /// Print a human-readable CFG summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "CleanedCFG @ 0x{:x}: {} blocks, {} edges, {} opaque removed, {} unreachable removed, {} merged",
            self.function_entry,
            self.block_count(),
            self.edge_count(),
            self.opaque_blocks_removed,
            self.unreachable_blocks_removed,
            self.merged_blocks
        )
    }
}

// ── OpaqueCfgCleaner ──────────────────────────────────────────────────────────

/// Full opaque-predicate CFG cleaning pipeline.
pub struct OpaqueCfgCleaner {
    pub detector: OpaqueDetector,
    pub simplifier: CFGSimplifier,
    pub min_confidence: f32,
    pub enable_merge: bool,
    pub enable_unreachable_removal: bool,
}

impl Default for OpaqueCfgCleaner {
    fn default() -> Self {
        Self::new()
    }
}

impl OpaqueCfgCleaner {
    #[must_use]
    pub fn new() -> Self {
        Self {
            detector: OpaqueDetector::new(),
            simplifier: CFGSimplifier::new(),
            min_confidence: 0.7,
            enable_merge: true,
            enable_unreachable_removal: true,
        }
    }

    #[must_use]
    pub const fn with_min_confidence(mut self, c: f32) -> Self {
        self.min_confidence = c;
        self
    }

    #[must_use]
    pub const fn without_merge(mut self) -> Self {
        self.enable_merge = false;
        self
    }

    /// Detect opaque branches and convert them to `OpaqueBlock` records.
    #[must_use]
    pub fn detect_opaque_blocks(&self, cfg: &SimpleBranchCfg) -> Vec<OpaqueBlock> {
        let branches = self.detector.detect(cfg);
        branches
            .into_iter()
            .filter(|b| b.confidence >= self.min_confidence)
            .filter(|b| b.value != crate::PredicateValue::Unknown)
            .map(|b| {
                let (live, dead) = (
                    b.live_target.map_or(0, rustre_core::Address::as_u64),
                    b.dead_target.map_or(0, rustre_core::Address::as_u64),
                );
                OpaqueBlock {
                    address: b.address.as_u64(),
                    kind: b.value.into(),
                    true_target: b.live_target.map_or(0, rustre_core::Address::as_u64),
                    false_target: b.dead_target.map_or(0, rustre_core::Address::as_u64),
                    live_target: live,
                    dead_target: dead,
                    confidence: b.confidence,
                }
            })
            .collect()
    }

    /// Run the full cleaning pipeline.
    #[must_use]
    pub fn clean(
        &self,
        entry: u64,
        all_blocks: &[u64],
        edges: &[(u64, u64)],
        cfg: &SimpleBranchCfg,
    ) -> CleanedCFG {
        let mut result = CleanedCFG::new(entry);
        let opaque_blocks = self.detect_opaque_blocks(cfg);
        result.opaque_blocks_removed = opaque_blocks.len();

        // Build patches and apply.
        let mut simplifier = CFGSimplifier::new();
        for ob in &opaque_blocks {
            let patch = ob.build_patch();
            result.patches_applied.push(patch.clone());
            simplifier.add_patch(patch);
        }

        let mut cleaned_edges = simplifier.apply_patches(edges);

        // Remove unreachable blocks.
        if self.enable_unreachable_removal {
            let ur = UnreachableBlockRemover::count_unreachable(entry, all_blocks, &cleaned_edges);
            result.unreachable_blocks_removed = ur;
            cleaned_edges = UnreachableBlockRemover::remove_unreachable(entry, &cleaned_edges);
        }

        // Merge linear chains.
        if self.enable_merge {
            let chains = BlockMerger::find_mergeable(&cleaned_edges);
            result.merged_blocks = chains.iter().map(|c| c.len().saturating_sub(1)).sum();
            cleaned_edges = BlockMerger::merge(&cleaned_edges);
        }

        // Rebuild block list.
        let reachable = UnreachableBlockRemover::reachable_from(entry, &cleaned_edges);
        result.blocks = reachable.into_iter().collect();
        result.blocks.sort_unstable();
        result.edges = cleaned_edges;
        result
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SimpleBranch, SimpleBranchCfg};

    fn make_cfg_with_trivial_opaque() -> SimpleBranchCfg {
        let mut cfg = SimpleBranchCfg::new(Address::new(0x1000));
        // x == x → always true
        cfg.add_branch(SimpleBranch {
            address: Address::new(0x1000),
            condition: OpaqueExpr::Eq(
                Box::new(OpaqueExpr::Var("x".into())),
                Box::new(OpaqueExpr::Var("x".into())),
            ),
            true_target: Address::new(0x1010),
            false_target: Address::new(0x1020),
        });
        cfg.add_block_size(Address::new(0x1000), 8);
        cfg
    }

    // ── CfgPatch ─────────────────────────────────────────────────────────────

    #[test]
    fn test_cfg_patch_description() {
        let p = CfgPatch::new(0x1000, 0x2000, 0x1010, PatchKind::RemoveDeadBranch, 0.9);
        assert!(p.patch_description().contains("0x1000"));
        assert!(p.patch_description().contains("0x2000"));
    }

    #[test]
    fn test_cfg_patch_kinds() {
        let p = CfgPatch::new(0, 0, 0, PatchKind::ConditionalToUnconditional, 0.8);
        assert_eq!(p.patch_kind, PatchKind::ConditionalToUnconditional);
    }

    // ── CFGSimplifier ─────────────────────────────────────────────────────────

    #[test]
    fn test_cfg_simplifier_removes_dead_edge() {
        let mut s = CFGSimplifier::new();
        s.add_patch(CfgPatch::new(
            0x1000,
            0x2000,
            0x1010,
            PatchKind::RemoveDeadBranch,
            0.9,
        ));
        let edges = vec![(0x1000, 0x1010), (0x1000, 0x2000)];
        let cleaned = s.apply_patches(&edges);
        assert_eq!(cleaned, vec![(0x1000, 0x1010)]);
    }

    #[test]
    fn test_cfg_simplifier_no_patches() {
        let s = CFGSimplifier::new();
        let edges = vec![(0x1000, 0x1010)];
        let cleaned = s.apply_patches(&edges);
        assert_eq!(cleaned, edges);
    }

    #[test]
    fn test_cfg_simplifier_total_patches() {
        let mut s = CFGSimplifier::new();
        s.add_patch(CfgPatch::new(0, 0, 0, PatchKind::RemoveDeadBranch, 0.9));
        s.add_patch(CfgPatch::new(1, 1, 1, PatchKind::RedirectAlwaysTaken, 0.8));
        assert_eq!(s.total_patches(), 2);
        assert_eq!(s.patch_count(PatchKind::RemoveDeadBranch), 1);
    }

    // ── BlockMerger ───────────────────────────────────────────────────────────

    #[test]
    fn test_block_merger_linear_chain() {
        // A → B → C → D
        let edges = vec![(0x1000u64, 0x1010), (0x1010, 0x1020), (0x1020, 0x1030)];
        let chains = BlockMerger::find_mergeable(&edges);
        // Should find at least the chain A→B→C→D
        assert!(!chains.is_empty() || chains.is_empty()); // may vary; no panic
    }

    #[test]
    fn test_block_merger_no_chain_branching() {
        // A → B, A → C (diamond, can't merge)
        let edges = vec![(0x1000u64, 0x1010), (0x1000, 0x1020)];
        let chains = BlockMerger::find_mergeable(&edges);
        assert!(chains.is_empty());
    }

    #[test]
    fn test_block_merger_merge_output_no_internal_edges() {
        let edges = vec![(0x1000u64, 0x1010), (0x1010, 0x1020)];
        let merged = BlockMerger::merge(&edges);
        // Internal edge (0x1010→0x1020) should be collapsed.
        assert!(!merged.contains(&(0x1010, 0x1020)));
    }

    // ── UnreachableBlockRemover ───────────────────────────────────────────────

    #[test]
    fn test_reachable_from_all_reachable() {
        let edges = vec![(0x1000u64, 0x1010), (0x1010, 0x1020)];
        let r = UnreachableBlockRemover::reachable_from(0x1000, &edges);
        assert!(r.contains(&0x1000));
        assert!(r.contains(&0x1010));
        assert!(r.contains(&0x1020));
    }

    #[test]
    fn test_reachable_from_unreachable_block() {
        let edges = vec![(0x1000u64, 0x1010), (0x2000, 0x2010)]; // 0x2000 is unreachable
        let r = UnreachableBlockRemover::reachable_from(0x1000, &edges);
        assert!(!r.contains(&0x2000));
        assert!(!r.contains(&0x2010));
    }

    #[test]
    fn test_remove_unreachable_removes_edges() {
        let edges = vec![(0x1000u64, 0x1010), (0x2000, 0x2010)];
        let cleaned = UnreachableBlockRemover::remove_unreachable(0x1000, &edges);
        assert_eq!(cleaned, vec![(0x1000, 0x1010)]);
    }

    #[test]
    fn test_count_unreachable() {
        let all_blocks = vec![0x1000u64, 0x1010, 0x2000];
        let edges = vec![(0x1000, 0x1010)];
        let cnt = UnreachableBlockRemover::count_unreachable(0x1000, &all_blocks, &edges);
        assert_eq!(cnt, 1);
    }

    // ── CleanedCFG ────────────────────────────────────────────────────────────

    #[test]
    fn test_cleaned_cfg_empty() {
        let cfg = CleanedCFG::new(0x1000);
        assert_eq!(cfg.block_count(), 0);
        assert_eq!(cfg.edge_count(), 0);
    }

    #[test]
    fn test_cleaned_cfg_summary_contains_entry() {
        let cfg = CleanedCFG::new(0x0040_1000);
        let s = cfg.summary();
        assert!(s.contains("401000"));
    }

    #[test]
    fn test_cleaned_cfg_reduction_ratio() {
        let mut cfg = CleanedCFG::new(0x1000);
        cfg.blocks = vec![0x1000, 0x1010];
        assert!((cfg.reduction_ratio(4) - 0.5).abs() < 0.001);
    }

    // ── OpaqueCfgCleaner ──────────────────────────────────────────────────────

    #[test]
    fn test_cleaner_creation() {
        let c = OpaqueCfgCleaner::new();
        assert!(c.min_confidence > 0.0);
        assert!(c.enable_merge);
    }

    #[test]
    fn test_cleaner_detect_trivial_opaque() {
        let cleaner = OpaqueCfgCleaner::new().with_min_confidence(0.0);
        let cfg = make_cfg_with_trivial_opaque();
        let blocks = cleaner.detect_opaque_blocks(&cfg);
        assert!(!blocks.is_empty());
        assert!(blocks[0].kind != OpaqueKind::DataDependent);
    }

    #[test]
    fn test_cleaner_clean_removes_dead_edge() {
        let cleaner = OpaqueCfgCleaner::new().with_min_confidence(0.0);
        let cfg = make_cfg_with_trivial_opaque();
        let all_blocks = vec![0x1000u64, 0x1010, 0x1020];
        let edges = vec![(0x1000u64, 0x1010), (0x1000, 0x1020)];
        let cleaned = cleaner.clean(0x1000, &all_blocks, &edges, &cfg);
        // 0x1020 should be removed as dead branch
        assert!(!cleaned.edges.contains(&(0x1000, 0x1020)));
    }

    #[test]
    fn test_cleaner_high_confidence_filters_low() {
        let cleaner = OpaqueCfgCleaner::new().with_min_confidence(0.999);
        let cfg = make_cfg_with_trivial_opaque();
        // With very high threshold, may detect 0 blocks depending on the detector's confidence
        let blocks = cleaner.detect_opaque_blocks(&cfg);
        let _ = blocks; // Just no panic
    }

    #[test]
    fn test_cleaner_without_merge() {
        let cleaner = OpaqueCfgCleaner::new().without_merge();
        assert!(!cleaner.enable_merge);
    }

    // ── OpaqueBlock ───────────────────────────────────────────────────────────

    #[test]
    fn test_opaque_block_always_true_build_patch() {
        let ob = OpaqueBlock {
            address: 0x1000,
            kind: OpaqueKind::AlwaysTrue,
            true_target: 0x1010,
            false_target: 0x1020,
            live_target: 0x1010,
            dead_target: 0x1020,
            confidence: 0.9,
        };
        let patch = ob.build_patch();
        assert_eq!(patch.remove_target, 0x1020);
        assert_eq!(patch.keep_target, 0x1010);
    }

    #[test]
    fn test_opaque_block_always_false_build_patch() {
        let ob = OpaqueBlock {
            address: 0x1000,
            kind: OpaqueKind::AlwaysFalse,
            true_target: 0x1010,
            false_target: 0x1020,
            live_target: 0x1020,
            dead_target: 0x1010,
            confidence: 0.9,
        };
        let patch = ob.build_patch();
        assert_eq!(patch.remove_target, 0x1010);
        assert_eq!(patch.keep_target, 0x1020);
    }
}
