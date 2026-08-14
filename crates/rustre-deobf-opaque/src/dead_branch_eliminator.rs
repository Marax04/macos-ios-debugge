//! `dead_branch_eliminator.rs` — Dead branch elimination after opaque predicate resolution.
//!
//! After constant propagation or pattern detection resolves branch conditions,
//! this pass: marks unreachable blocks (successors of always-false/always-true branches),
//! removes dead instructions, patches branches to unconditional jumps, and updates the CFG.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// DeadBranch — a resolved opaque conditional branch
// ─────────────────────────────────────────────────────────────────────────────

/// A conditional branch that has been proven to always go one way.
#[derive(Debug, Clone)]
pub struct DeadBranch {
    /// Block id containing the conditional branch.
    pub block_id: u32,
    /// Index of the branch instruction within the block.
    pub instr_idx: usize,
    /// Whether the condition is always true (takes the true edge).
    pub always_true: bool,
    /// Always-taken target block id.
    pub live_target: u32,
    /// Never-taken (dead) target block id.
    pub dead_target: u32,
    /// Original address hint (if available).
    pub address_hint: Option<u64>,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
}

impl fmt::Display for DeadBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = if self.always_true { "always-true" } else { "always-false" };
        write!(
            f,
            "DeadBranch @ block {} instr #{} {} live={} dead={} conf={:.2}",
            self.block_id, self.instr_idx, outcome,
            self.live_target, self.dead_target, self.confidence
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BranchPatch — rewrite rule for a single branch
// ─────────────────────────────────────────────────────────────────────────────

/// Describes how a conditional branch should be rewritten to an unconditional jump.
#[derive(Debug, Clone)]
pub struct BranchPatch {
    /// Block id to patch.
    pub block_id: u32,
    /// Index of the instruction being patched.
    pub instr_idx: usize,
    /// The single successor after patching.
    pub new_target: u32,
    /// Whether this was an always-true or always-false branch.
    pub was_always_true: bool,
}

impl fmt::Display for BranchPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BranchPatch @ block {} instr #{} → jump {}", self.block_id, self.instr_idx, self.new_target)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnreachableBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block that has been determined to be unreachable.
#[derive(Debug, Clone)]
pub struct UnreachableBlock {
    /// The block id.
    pub block_id: u32,
    /// Why it became unreachable.
    pub reason: UnreachableReason,
    /// Address hint.
    pub address_hint: Option<u64>,
}

/// Why a block is unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreachableReason {
    /// This block is the never-taken target of an opaque predicate branch.
    DeadBranchTarget,
    /// All predecessors are unreachable (transitively unreachable).
    TransitivelyUnreachable,
    /// No predecessors exist (orphan block, not the entry).
    NoLivePredecessors,
}

impl fmt::Display for UnreachableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::DeadBranchTarget => "DeadBranchTarget",
            Self::TransitivelyUnreachable => "TransitivelyUnreachable",
            Self::NoLivePredecessors => "NoLivePredecessors",
        };
        write!(f, "{s}")
    }
}

impl fmt::Display for UnreachableBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnreachableBlock {} ({})", self.block_id, self.reason)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfgPatch — complete set of changes to apply to the CFG
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated patch for the entire CFG.
#[derive(Debug, Default)]
pub struct CfgPatch {
    /// Branch rewrite rules.
    pub branch_patches: Vec<BranchPatch>,
    /// Blocks that should be removed from the CFG.
    pub unreachable_blocks: Vec<UnreachableBlock>,
    /// Predecessor edges to remove (block_id → dead predecessor).
    pub pred_removals: Vec<(u32, u32)>,
    /// Successor edges to remove (block_id → dead successor).
    pub succ_removals: Vec<(u32, u32)>,
    /// New unconditional edges to add (from → to).
    pub new_edges: Vec<(u32, u32)>,
}

impl CfgPatch {
    pub fn new() -> Self { Self::default() }

    pub fn is_empty(&self) -> bool {
        self.branch_patches.is_empty() && self.unreachable_blocks.is_empty()
    }

    pub fn total_changes(&self) -> usize {
        self.branch_patches.len() + self.unreachable_blocks.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EliminationResult
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of the dead branch elimination pass.
#[derive(Debug)]
pub struct EliminationResult {
    /// Number of conditional branches patched to unconditional jumps.
    pub branches_patched: usize,
    /// Number of blocks removed as unreachable.
    pub blocks_removed: usize,
    /// Number of instructions removed from dead blocks.
    pub instrs_removed: usize,
    /// CFG patch to be applied.
    pub patch: CfgPatch,
    /// All detected dead branches (input to the pass).
    pub dead_branches: Vec<DeadBranch>,
    /// All identified unreachable blocks.
    pub unreachable: Vec<UnreachableBlock>,
    /// Warnings generated during elimination.
    pub warnings: Vec<String>,
}

impl EliminationResult {
    fn new() -> Self {
        Self {
            branches_patched: 0,
            blocks_removed: 0,
            instrs_removed: 0,
            patch: CfgPatch::new(),
            dead_branches: Vec::new(),
            unreachable: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Whether any changes were made.
    pub fn changed(&self) -> bool { self.branches_patched > 0 || self.blocks_removed > 0 }
}

impl fmt::Display for EliminationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EliminationResult: patched={} removed_blocks={} removed_instrs={}",
            self.branches_patched, self.blocks_removed, self.instrs_removed
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Simplified CFG representation
// ─────────────────────────────────────────────────────────────────────────────

/// Instruction in a simplified CFG block.
#[derive(Debug, Clone, PartialEq)]
pub enum CfgInstr {
    /// Conditional branch: if cond != 0 goto true_block, else false_block.
    CondBr { cond_var: u32, true_block: u32, false_block: u32 },
    /// Unconditional jump.
    Jump(u32),
    /// Any non-branch instruction (represented opaquely for this pass).
    Other { dst: Option<u32>, text: String },
    /// Return.
    Ret,
}

impl CfgInstr {
    pub fn is_branch(&self) -> bool {
        matches!(self, Self::CondBr { .. } | Self::Jump(_))
    }

    pub fn successors(&self) -> Vec<u32> {
        match self {
            Self::CondBr { true_block, false_block, .. } => vec![*true_block, *false_block],
            Self::Jump(t) => vec![*t],
            _ => vec![],
        }
    }
}

/// A basic block in the simplified CFG.
#[derive(Debug, Clone)]
pub struct CfgBlock {
    pub id: u32,
    pub instrs: Vec<CfgInstr>,
    pub preds: Vec<u32>,
    pub succs: Vec<u32>,
    pub address: Option<u64>,
    /// Whether this block has been marked as dead.
    pub is_dead: bool,
}

impl CfgBlock {
    pub fn new(id: u32) -> Self {
        Self { id, instrs: Vec::new(), preds: Vec::new(), succs: Vec::new(), address: None, is_dead: false }
    }

    pub fn with_address(mut self, a: u64) -> Self { self.address = Some(a); self }

    pub fn add_instr(&mut self, i: CfgInstr) { self.instrs.push(i); }

    /// Find the index of the terminating branch instruction, if any.
    pub fn branch_instr_idx(&self) -> Option<usize> {
        self.instrs.iter().rposition(|i| i.is_branch())
    }
}

/// Simple mutable CFG.
pub struct Cfg {
    pub blocks: Vec<CfgBlock>,
    /// Entry block id.
    pub entry: u32,
}

impl Cfg {
    pub fn new(entry: u32) -> Self { Self { blocks: Vec::new(), entry } }

    pub fn add_block(&mut self, block: CfgBlock) { self.blocks.push(block); }

    fn block_by_id_mut(&mut self, id: u32) -> Option<&mut CfgBlock> {
        self.blocks.iter_mut().find(|b| b.id == id)
    }

    fn block_by_id(&self, id: u32) -> Option<&CfgBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Rebuild successor/predecessor edges by scanning branch instructions.
    pub fn rebuild_edges(&mut self) {
        // First clear all edges.
        for b in &mut self.blocks { b.succs.clear(); b.preds.clear(); }

        let succ_info: Vec<(u32, Vec<u32>)> = self.blocks.iter()
            .map(|b| (b.id, b.instrs.iter().flat_map(|i| i.successors()).collect()))
            .collect();

        for (id, succs) in &succ_info {
            if let Some(b) = self.block_by_id_mut(*id) { b.succs = succs.clone(); }
        }

        let mut pred_map: HashMap<u32, Vec<u32>> = HashMap::new();
        for (id, succs) in &succ_info {
            for &s in succs { pred_map.entry(s).or_default().push(*id); }
        }
        for (id, preds) in pred_map {
            if let Some(b) = self.block_by_id_mut(id) { b.preds = preds; }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeadBranchEliminator
// ─────────────────────────────────────────────────────────────────────────────

/// Eliminates dead branches from a CFG given a set of `DeadBranch` descriptors.
pub struct DeadBranchEliminator {
    /// Whether to perform transitive unreachability propagation.
    pub transitive: bool,
    /// Whether to actually remove instructions from dead blocks.
    pub remove_instrs: bool,
    /// Whether to remove dead blocks from the CFG (otherwise just marks them).
    pub remove_blocks: bool,
}

impl DeadBranchEliminator {
    pub fn new() -> Self {
        Self { transitive: true, remove_instrs: true, remove_blocks: true }
    }

    pub fn without_transitive(mut self) -> Self { self.transitive = false; self }
    pub fn without_remove_blocks(mut self) -> Self { self.remove_blocks = false; self }

    /// Run dead branch elimination on `cfg` given a list of `dead_branches`.
    pub fn eliminate(&self, cfg: &mut Cfg, dead_branches: &[DeadBranch]) -> EliminationResult {
        let mut result = EliminationResult::new();
        result.dead_branches = dead_branches.to_vec();

        // Phase 1: patch branches to unconditional jumps.
        let mut initially_dead: HashSet<u32> = HashSet::new();
        for db in dead_branches {
            if let Some(block) = cfg.block_by_id_mut(db.block_id) {
                if let Some(idx) = block.branch_instr_idx() {
                    if idx == db.instr_idx || db.instr_idx == usize::MAX {
                        // Rewrite to unconditional jump.
                        block.instrs[idx] = CfgInstr::Jump(db.live_target);
                        result.branches_patched += 1;
                        result.patch.branch_patches.push(BranchPatch {
                            block_id: db.block_id,
                            instr_idx: idx,
                            new_target: db.live_target,
                            was_always_true: db.always_true,
                        });
                        initially_dead.insert(db.dead_target);
                        result.patch.succ_removals.push((db.block_id, db.dead_target));
                        result.patch.new_edges.push((db.block_id, db.live_target));
                    } else {
                        result.warnings.push(format!(
                            "DeadBranch instr_idx {} does not match found branch idx {} in block {}",
                            db.instr_idx, idx, db.block_id
                        ));
                    }
                } else {
                    result.warnings.push(format!("No branch found in block {}", db.block_id));
                }
            } else {
                result.warnings.push(format!("Block {} not found", db.block_id));
            }
        }

        // Rebuild edges after patching.
        cfg.rebuild_edges();

        // Only the EDGE `block_id -> dead_target` is guaranteed to die. The
        // TARGET may well survive, reached by another path — in
        // `0: CondBr(t=1,f=2); 1: Jump(2); 2: Ret` block 2 is still reached
        // through `0 -> 1 -> 2`.
        //
        // Seeding it unconditionally put it in the dead set as an axiom, and
        // `find_unreachable` never re-examines its seeds however careful its
        // BFS is. The block was then removed while block 1 still jumped to it,
        // leaving the CFG naming a block that no longer exists.
        //
        // Keep as seeds only the targets that really became unreachable now
        // that the edges have been rebuilt.
        let reachable = Self::reachable_from_entry(cfg);
        initially_dead.retain(|id| !reachable.contains(id));

        // Phase 2: find unreachable blocks.
        let unreachable = self.find_unreachable(cfg, &initially_dead);

        // Phase 3: mark/remove dead blocks.
        for &dead_id in &unreachable {
            let reason = if initially_dead.contains(&dead_id) {
                UnreachableReason::DeadBranchTarget
            } else {
                UnreachableReason::TransitivelyUnreachable
            };

            let addr_hint = cfg.block_by_id(dead_id).and_then(|b| b.address);
            let ub = UnreachableBlock { block_id: dead_id, reason, address_hint: addr_hint };
            result.unreachable.push(ub.clone());
            result.patch.unreachable_blocks.push(ub);

            if let Some(block) = cfg.block_by_id_mut(dead_id) {
                block.is_dead = true;
                if self.remove_instrs {
                    result.instrs_removed += block.instrs.len();
                    block.instrs.clear();
                }
            }
        }

        if self.remove_blocks {
            let dead_set: HashSet<u32> = unreachable.iter().copied().collect();
            cfg.blocks.retain(|b| !dead_set.contains(&b.id));
            result.blocks_removed = dead_set.len();
        }

        // Remove dead predecessor references from live blocks.
        for block in &mut cfg.blocks {
            let _before = block.preds.len();
            block.preds.retain(|p| {
                let keep = !result.unreachable.iter().any(|u| u.block_id == *p);
                if !keep {
                    result.patch.pred_removals.push((block.id, *p));
                }
                keep
            });
        }

        result
    }

    /// Block ids reachable from the entry by following successor edges.
    ///
    /// Used to tell "this edge died" from "this block died": only a block that
    /// no path from the entry can still reach is genuinely dead.
    fn reachable_from_entry(cfg: &Cfg) -> HashSet<u32> {
        let mut seen: HashSet<u32> = HashSet::new();
        let mut queue: VecDeque<u32> = VecDeque::new();
        if cfg.block_by_id(cfg.entry).is_some() {
            seen.insert(cfg.entry);
            queue.push_back(cfg.entry);
        }
        while let Some(id) = queue.pop_front() {
            if let Some(block) = cfg.block_by_id(id) {
                for &succ in &block.succs {
                    if seen.insert(succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }
        seen
    }

    /// Compute the set of unreachable block ids by BFS from `initially_dead`.
    fn find_unreachable(&self, cfg: &Cfg, initially_dead: &HashSet<u32>) -> Vec<u32> {
        if !self.transitive {
            return initially_dead.iter().copied().collect();
        }

        // BFS forward from the initially dead set.
        let mut dead: HashSet<u32> = initially_dead.clone();
        let mut queue: VecDeque<u32> = initially_dead.iter().copied().collect();

        while let Some(id) = queue.pop_front() {
            if let Some(block) = cfg.block_by_id(id) {
                for &succ in &block.succs {
                    // A successor is transitively dead if ALL its predecessors are dead.
                    if !dead.contains(&succ) && self.all_preds_dead(cfg, succ, &dead) {
                        dead.insert(succ);
                        queue.push_back(succ);
                    }
                }
            }
        }

        // Also mark orphan blocks (no predecessors, not entry).
        let entry = cfg.entry;
        for block in &cfg.blocks {
            if block.id != entry && block.preds.is_empty() && !dead.contains(&block.id) {
                dead.insert(block.id);
            }
        }

        let mut result: Vec<u32> = dead.into_iter().collect();
        result.sort_unstable();
        result
    }

    fn all_preds_dead(&self, cfg: &Cfg, block_id: u32, dead: &HashSet<u32>) -> bool {
        if let Some(block) = cfg.block_by_id(block_id) {
            !block.preds.is_empty() && block.preds.iter().all(|p| dead.contains(p))
        } else {
            false
        }
    }

    /// Analyse `dead_branches` and `cfg` to produce a `CfgPatch` without applying it.
    pub fn plan(&self, cfg: &Cfg, dead_branches: &[DeadBranch]) -> CfgPatch {
        let mut patch = CfgPatch::new();
        let mut initially_dead: HashSet<u32> = HashSet::new();

        for db in dead_branches {
            if let Some(block) = cfg.block_by_id(db.block_id) {
                if let Some(idx) = block.branch_instr_idx() {
                    patch.branch_patches.push(BranchPatch {
                        block_id: db.block_id,
                        instr_idx: idx,
                        new_target: db.live_target,
                        was_always_true: db.always_true,
                    });
                    patch.succ_removals.push((db.block_id, db.dead_target));
                    patch.new_edges.push((db.block_id, db.live_target));
                    initially_dead.insert(db.dead_target);
                }
            }
        }

        let unreachable = self.find_unreachable(cfg, &initially_dead);
        for dead_id in unreachable {
            let reason = if initially_dead.contains(&dead_id) {
                UnreachableReason::DeadBranchTarget
            } else {
                UnreachableReason::TransitivelyUnreachable
            };
            let addr = cfg.block_by_id(dead_id).and_then(|b| b.address);
            patch.unreachable_blocks.push(UnreachableBlock { block_id: dead_id, reason, address_hint: addr });
        }

        patch
    }
}

impl Default for DeadBranchEliminator {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: build test CFGs
// ─────────────────────────────────────────────────────────────────────────────

/// Build a simple two-branch CFG for tests.
///
/// ```text
/// block 0: condbr(cond=0) -> true=1, false=2
/// block 1: ret
/// block 2: ret
/// ```
pub fn two_branch_cfg() -> Cfg {
    let mut cfg = Cfg::new(0);
    let mut b0 = CfgBlock::new(0);
    b0.add_instr(CfgInstr::CondBr { cond_var: 0, true_block: 1, false_block: 2 });
    let mut b1 = CfgBlock::new(1);
    b1.add_instr(CfgInstr::Ret);
    let mut b2 = CfgBlock::new(2);
    b2.add_instr(CfgInstr::Ret);
    cfg.add_block(b0);
    cfg.add_block(b1);
    cfg.add_block(b2);
    cfg.rebuild_edges();
    cfg
}

/// Build a chain CFG: 0 → 1 → 2, with a dead branch at 0 to dead block 3.
pub fn chain_with_dead_branch() -> Cfg {
    let mut cfg = Cfg::new(0);
    let mut b0 = CfgBlock::new(0);
    b0.add_instr(CfgInstr::CondBr { cond_var: 0, true_block: 1, false_block: 3 });
    let mut b1 = CfgBlock::new(1);
    b1.add_instr(CfgInstr::Jump(2));
    let mut b2 = CfgBlock::new(2);
    b2.add_instr(CfgInstr::Ret);
    let mut b3 = CfgBlock::new(3);
    b3.add_instr(CfgInstr::Ret);
    let mut b4 = CfgBlock::new(4);
    b4.add_instr(CfgInstr::Jump(5));
    let mut b5 = CfgBlock::new(5);
    b5.add_instr(CfgInstr::Ret);
    // b3 → b4 → b5 are transitively dead once b3 is dead.
    b3.instrs.clear();
    b3.add_instr(CfgInstr::Jump(4));
    cfg.add_block(b0);
    cfg.add_block(b1);
    cfg.add_block(b2);
    cfg.add_block(b3);
    cfg.add_block(b4);
    cfg.add_block(b5);
    cfg.rebuild_edges();
    cfg
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_two_branch_eliminate_false() {
        let mut cfg = two_branch_cfg();
        let db = vec![DeadBranch {
            block_id: 0,
            instr_idx: usize::MAX,
            always_true: true,
            live_target: 1,
            dead_target: 2,
            address_hint: None,
            confidence: 1.0,
        }];
        let elim = DeadBranchEliminator::new();
        let result = elim.eliminate(&mut cfg, &db);
        assert_eq!(result.branches_patched, 1);
        assert_eq!(result.blocks_removed, 1);
        // Block 2 should be gone.
        assert!(cfg.blocks.iter().all(|b| b.id != 2));
    }

    #[test]
    fn test_always_false_branch_eliminates_true_target() {
        let mut cfg = two_branch_cfg();
        let db = vec![DeadBranch {
            block_id: 0,
            instr_idx: usize::MAX,
            always_true: false,
            live_target: 2,
            dead_target: 1,
            address_hint: None,
            confidence: 0.95,
        }];
        let elim = DeadBranchEliminator::new();
        let result = elim.eliminate(&mut cfg, &db);
        assert_eq!(result.branches_patched, 1);
        assert!(cfg.blocks.iter().all(|b| b.id != 1));
    }

    #[test]
    fn test_transitive_unreachability() {
        let mut cfg = chain_with_dead_branch();
        let db = vec![DeadBranch {
            block_id: 0,
            instr_idx: usize::MAX,
            always_true: true,
            live_target: 1,
            dead_target: 3,
            address_hint: None,
            confidence: 1.0,
        }];
        let elim = DeadBranchEliminator::new();
        let result = elim.eliminate(&mut cfg, &db);
        // Blocks 3, 4, 5 should all be removed.
        assert!(result.blocks_removed >= 3);
    }

    #[test]
    fn test_plan_does_not_modify_cfg() {
        let cfg = two_branch_cfg();
        let original_len = cfg.blocks.len();
        let db = vec![DeadBranch {
            block_id: 0,
            instr_idx: usize::MAX,
            always_true: true,
            live_target: 1,
            dead_target: 2,
            address_hint: None,
            confidence: 1.0,
        }];
        let elim = DeadBranchEliminator::new();
        let patch = elim.plan(&cfg, &db);
        assert_eq!(cfg.blocks.len(), original_len);
        assert!(!patch.branch_patches.is_empty());
    }

    #[test]
    fn test_no_dead_branches() {
        let mut cfg = two_branch_cfg();
        let elim = DeadBranchEliminator::new();
        let result = elim.eliminate(&mut cfg, &[]);
        assert_eq!(result.branches_patched, 0);
        assert_eq!(result.blocks_removed, 0);
        assert!(!result.changed());
    }

    #[test]
    fn test_unreachable_block_display() {
        let ub = UnreachableBlock {
            block_id: 42,
            reason: UnreachableReason::DeadBranchTarget,
            address_hint: None,
        };
        let s = ub.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("DeadBranchTarget"));
    }

    #[test]
    fn test_dead_branch_display() {
        let db = DeadBranch {
            block_id: 5,
            instr_idx: 2,
            always_true: true,
            live_target: 6,
            dead_target: 7,
            address_hint: Some(0x1000),
            confidence: 0.95,
        };
        let s = db.to_string();
        assert!(s.contains("5"));
        assert!(s.contains("always-true"));
    }

    #[test]
    fn test_elimination_result_display() {
        let er = EliminationResult::new();
        let s = er.to_string();
        assert!(s.contains("patched=0"));
    }

    #[test]
    fn test_cfg_patch_total_changes() {
        let mut patch = CfgPatch::new();
        patch.branch_patches.push(BranchPatch { block_id: 0, instr_idx: 0, new_target: 1, was_always_true: true });
        assert_eq!(patch.total_changes(), 1);
    }
}
