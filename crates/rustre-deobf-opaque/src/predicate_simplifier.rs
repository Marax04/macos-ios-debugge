//! `predicate_simplifier` — opaque predicate simplification in IL.

use crate::{
    OpaqueDetector, OpaqueExpr, OpaquePredicateKind, PredicateValue, SimpleBranch, SimpleBranchCfg,
};
use rustre_core::address::Address;
use std::collections::HashMap;

// ── SimplificationResult ──────────────────────────────────────────────────────

/// Result of simplifying a single conditional branch.
#[derive(Debug, Clone)]
pub struct SimplificationResult {
    /// Address of the conditional jump instruction.
    pub address: Address,
    /// Original condition expression.
    pub old_cond: OpaqueExpr,
    /// Simplified condition (constant true/false) or original if not simplified.
    pub new_cond: OpaqueExpr,
    /// Whether the branch was identified as opaque.
    pub was_opaque: bool,
    /// The constant outcome, if opaque.
    pub outcome: PredicateValue,
    /// Detection method used.
    pub kind: OpaquePredicateKind,
}

impl SimplificationResult {
    /// Whether the branch was completely eliminated (replaced by unconditional).
    #[must_use]
    pub fn is_eliminated(&self) -> bool {
        self.was_opaque && self.outcome != PredicateValue::Unknown
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.is_eliminated() {
            format!(
                "{:#x}: eliminated ({}) via {:?}",
                self.address.as_u64(),
                self.outcome,
                self.kind
            )
        } else {
            format!("{:#x}: not simplified", self.address.as_u64())
        }
    }
}

// ── BasicBlock ────────────────────────────────────────────────────────────────

/// A simplified basic block in the IL CFG.
#[derive(Debug, Clone)]
pub struct IlBasicBlock {
    /// Start address of the block.
    pub start: Address,
    /// End address (exclusive).
    pub end: Address,
    /// Instruction count.
    pub insn_count: usize,
    /// Whether this block is reachable.
    pub reachable: bool,
    /// Successors: (`target_addr`, `is_conditional`).
    pub successors: Vec<(Address, bool)>,
}

impl IlBasicBlock {
    /// Create a new basic block.
    #[must_use]
    pub const fn new(start: Address, end: Address, insn_count: usize) -> Self {
        Self {
            start,
            end,
            insn_count,
            reachable: true,
            successors: Vec::new(),
        }
    }

    /// Add a successor edge.
    pub fn add_successor(&mut self, target: Address, conditional: bool) {
        self.successors.push((target, conditional));
    }

    /// Block size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.as_u64().saturating_sub(self.start.as_u64())
    }

    /// Whether this is a leaf block (no successors).
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.successors.is_empty()
    }
}

// ── PredicateSimplifier ───────────────────────────────────────────────────────

/// Pass over LLIL/MLIL-equivalent CFG that detects and simplifies opaque
/// predicates, replacing conditional branches with unconditional ones or NOPs.
pub struct PredicateSimplifier {
    pub detector: OpaqueDetector,
    /// Number of predicates simplified in this pass.
    pub simplified_count: usize,
    /// Number of dead blocks found.
    pub dead_blocks_found: usize,
}

impl Default for PredicateSimplifier {
    fn default() -> Self {
        Self {
            detector: OpaqueDetector::new(),
            simplified_count: 0,
            dead_blocks_found: 0,
        }
    }
}

impl PredicateSimplifier {
    /// Create a new simplifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the simplification pass over `cfg`.
    ///
    /// Returns a list of simplification results, one per branch.
    pub fn run(&mut self, cfg: &SimpleBranchCfg) -> Vec<SimplificationResult> {
        let mut results = Vec::with_capacity(cfg.branches.len());
        for branch in &cfg.branches {
            let (value, kind, confidence) = self.detector.classify_condition(&branch.condition);
            let was_opaque =
                value != PredicateValue::Unknown && confidence >= self.detector.min_confidence;
            if was_opaque {
                self.simplified_count += 1;
            }
            let new_cond = if was_opaque {
                match value {
                    PredicateValue::AlwaysTrue => OpaqueExpr::Const(1),
                    PredicateValue::AlwaysFalse => OpaqueExpr::Const(0),
                    PredicateValue::Unknown => branch.condition.clone(),
                }
            } else {
                branch.condition.simplify()
            };
            results.push(SimplificationResult {
                address: branch.address,
                old_cond: branch.condition.clone(),
                new_cond,
                was_opaque,
                outcome: value,
                kind,
            });
        }
        results
    }

    /// Simplify a single expression (no CFG context).
    #[must_use]
    pub fn simplify_expr(&self, expr: &OpaqueExpr) -> (OpaqueExpr, PredicateValue) {
        let (value, _, _) = self.detector.classify_condition(expr);
        let simplified = match value {
            PredicateValue::AlwaysTrue => OpaqueExpr::Const(1),
            PredicateValue::AlwaysFalse => OpaqueExpr::Const(0),
            PredicateValue::Unknown => expr.simplify(),
        };
        (simplified, value)
    }

    /// Apply simplification results to a mutable block map.
    ///
    /// Blocks whose only predecessor's conditional branch was always-false
    /// are marked unreachable.
    pub fn apply_to_blocks(
        &mut self,
        blocks: &mut HashMap<u64, IlBasicBlock>,
        results: &[SimplificationResult],
        cfg: &SimpleBranchCfg,
    ) {
        for (res, branch) in results.iter().zip(&cfg.branches) {
            if !res.was_opaque {
                continue;
            }
            // The dead target depends on the outcome.
            let dead_addr = match res.outcome {
                PredicateValue::AlwaysTrue => Some(branch.false_target.as_u64()),
                PredicateValue::AlwaysFalse => Some(branch.true_target.as_u64()),
                PredicateValue::Unknown => None,
            };
            if let Some(addr) = dead_addr
                && let Some(block) = blocks.get_mut(&addr) {
                    block.reachable = false;
                    self.dead_blocks_found += 1;
                }
        }
    }
}

// ── DeadCodeEliminator ────────────────────────────────────────────────────────

/// Removes unreachable basic blocks from an IL CFG.
pub struct DeadCodeEliminator;

impl DeadCodeEliminator {
    /// Create a new eliminator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Mark all blocks reachable from `entry` in `blocks` via forward DFS.
    pub fn mark_reachable(entry: Address, blocks: &mut HashMap<u64, IlBasicBlock>) {
        let mut stack = vec![entry.as_u64()];
        let mut visited = std::collections::HashSet::new();

        while let Some(addr) = stack.pop() {
            if !visited.insert(addr) {
                continue;
            }
            if let Some(block) = blocks.get_mut(&addr) {
                block.reachable = true;
                let succs: Vec<u64> = block.successors.iter().map(|(s, _)| s.as_u64()).collect();
                for s in succs {
                    if !visited.contains(&s) {
                        stack.push(s);
                    }
                }
            }
        }
    }

    /// Remove all blocks not marked reachable.
    ///
    /// Returns the number of blocks removed.
    pub fn eliminate(&self, blocks: &mut HashMap<u64, IlBasicBlock>) -> usize {
        let dead: Vec<u64> = blocks
            .iter()
            .filter(|(_, b)| !b.reachable)
            .map(|(&a, _)| a)
            .collect();
        let count = dead.len();
        for addr in dead {
            blocks.remove(&addr);
        }
        count
    }

    /// Count dead blocks.
    #[must_use]
    pub fn count_dead(blocks: &HashMap<u64, IlBasicBlock>) -> usize {
        blocks.values().filter(|b| !b.reachable).count()
    }
}

impl Default for DeadCodeEliminator {
    fn default() -> Self {
        Self::new()
    }
}

// ── IlCfg ─────────────────────────────────────────────────────────────────────

/// A complete IL CFG that can be simplified and cleaned up.
#[derive(Debug, Default)]
pub struct IlCfg {
    pub blocks: HashMap<u64, IlBasicBlock>,
    pub entry: Option<Address>,
    pub branches: Vec<SimpleBranch>,
}

impl IlCfg {
    /// Create a new empty CFG.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the entry point.
    pub fn set_entry(&mut self, entry: Address) {
        self.entry = Some(entry);
        // Ensure the entry block exists and is reachable.
        let block = self
            .blocks
            .entry(entry.as_u64())
            .or_insert_with(|| IlBasicBlock::new(entry, Address::new(entry.as_u64() + 1), 1));
        block.reachable = true;
    }

    /// Add a basic block.
    pub fn add_block(&mut self, block: IlBasicBlock) {
        self.blocks.insert(block.start.as_u64(), block);
    }

    /// Add a conditional branch.
    pub fn add_branch(&mut self, branch: SimpleBranch) {
        self.branches.push(branch);
    }

    /// Run the full simplification pipeline.
    pub fn simplify(&mut self) -> SimplificationStats {
        let cfg = SimpleBranchCfg {
            function_start: self.entry.unwrap_or_else(|| Address::new(0)),
            branches: self.branches.clone(),
            block_sizes: HashMap::new(),
        };

        let mut simplifier = PredicateSimplifier::new();
        let results = simplifier.run(&cfg);
        simplifier.apply_to_blocks(&mut self.blocks, &results, &cfg);

        if let Some(entry) = self.entry {
            // Reset reachability and recompute.
            for b in self.blocks.values_mut() {
                b.reachable = false;
            }
            DeadCodeEliminator::mark_reachable(entry, &mut self.blocks);
        }

        let elim = DeadCodeEliminator::new();
        let dead_removed = elim.eliminate(&mut self.blocks);

        SimplificationStats {
            branches_simplified: simplifier.simplified_count,
            dead_blocks_removed: dead_removed,
            total_branches: cfg.branches.len(),
        }
    }

    /// Number of blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of reachable blocks.
    #[must_use]
    pub fn reachable_count(&self) -> usize {
        self.blocks.values().filter(|b| b.reachable).count()
    }
}

/// Summary statistics from a simplification run.
#[derive(Debug, Clone)]
pub struct SimplificationStats {
    pub branches_simplified: usize,
    pub dead_blocks_removed: usize,
    pub total_branches: usize,
}

impl SimplificationStats {
    /// Simplification rate (simplified / total).
    #[must_use]
    pub fn simplification_rate(&self) -> f64 {
        if self.total_branches == 0 {
            0.0
        } else {
            self.branches_simplified as f64 / self.total_branches as f64
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u64) -> Address {
        Address::new(n)
    }
    fn x() -> OpaqueExpr {
        OpaqueExpr::Var("x".into())
    }

    fn make_cfg_with_opaque() -> SimpleBranchCfg {
        let mut cfg = SimpleBranchCfg::new(addr(0));
        // Always-true branch: x == x
        cfg.add_branch(SimpleBranch {
            address: addr(0x1000),
            condition: OpaqueExpr::Eq(Box::new(x()), Box::new(x())),
            true_target: addr(0x2000),
            false_target: addr(0x3000),
        });
        // Always-false: x != x
        cfg.add_branch(SimpleBranch {
            address: addr(0x1010),
            condition: OpaqueExpr::Ne(Box::new(x()), Box::new(x())),
            true_target: addr(0x4000),
            false_target: addr(0x5000),
        });
        cfg
    }

    #[test]
    fn test_simplification_result_eliminated() {
        let r = SimplificationResult {
            address: addr(0x1000),
            old_cond: x(),
            new_cond: OpaqueExpr::Const(1),
            was_opaque: true,
            outcome: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::TrivialIdentity,
        };
        assert!(r.is_eliminated());
    }

    #[test]
    fn test_simplification_result_not_eliminated() {
        let r = SimplificationResult {
            address: addr(0),
            old_cond: x(),
            new_cond: x(),
            was_opaque: false,
            outcome: PredicateValue::Unknown,
            kind: OpaquePredicateKind::Symbolic,
        };
        assert!(!r.is_eliminated());
    }

    #[test]
    fn test_simplification_result_summary() {
        let r = SimplificationResult {
            address: addr(0x1234),
            old_cond: x(),
            new_cond: OpaqueExpr::Const(1),
            was_opaque: true,
            outcome: PredicateValue::AlwaysTrue,
            kind: OpaquePredicateKind::TrivialIdentity,
        };
        let s = r.summary();
        assert!(s.contains("0x1234"));
        assert!(s.contains("eliminated"));
    }

    #[test]
    fn test_il_basic_block_new() {
        let b = IlBasicBlock::new(addr(0), addr(10), 3);
        assert!(b.reachable);
        assert_eq!(b.insn_count, 3);
        assert_eq!(b.size(), 10);
    }

    #[test]
    fn test_il_basic_block_is_leaf() {
        let b = IlBasicBlock::new(addr(0), addr(4), 1);
        assert!(b.is_leaf());
    }

    #[test]
    fn test_il_basic_block_add_successor() {
        let mut b = IlBasicBlock::new(addr(0), addr(4), 1);
        b.add_successor(addr(10), true);
        assert_eq!(b.successors.len(), 1);
        assert!(!b.is_leaf());
    }

    #[test]
    fn test_predicate_simplifier_run_opaque() {
        let cfg = make_cfg_with_opaque();
        let mut simplifier = PredicateSimplifier::new();
        let results = simplifier.run(&cfg);
        assert_eq!(results.len(), 2);
        assert!(results[0].was_opaque);
        assert!(results[1].was_opaque);
        assert_eq!(simplifier.simplified_count, 2);
    }

    #[test]
    fn test_predicate_simplifier_run_non_opaque() {
        let mut cfg = SimpleBranchCfg::new(addr(0));
        cfg.add_branch(SimpleBranch {
            address: addr(0x100),
            condition: OpaqueExpr::Lt(Box::new(x()), Box::new(OpaqueExpr::Var("y".into()))),
            true_target: addr(0x200),
            false_target: addr(0x300),
        });
        let mut simplifier = PredicateSimplifier::new();
        let results = simplifier.run(&cfg);
        assert!(!results[0].was_opaque);
    }

    #[test]
    fn test_simplifier_new_cond_for_true() {
        let cfg = make_cfg_with_opaque();
        let mut simplifier = PredicateSimplifier::new();
        let results = simplifier.run(&cfg);
        assert_eq!(results[0].new_cond, OpaqueExpr::Const(1));
    }

    #[test]
    fn test_simplifier_new_cond_for_false() {
        let cfg = make_cfg_with_opaque();
        let mut simplifier = PredicateSimplifier::new();
        let results = simplifier.run(&cfg);
        assert_eq!(results[1].new_cond, OpaqueExpr::Const(0));
    }

    #[test]
    fn test_simplifier_simplify_expr_tautology() {
        let simplifier = PredicateSimplifier::new();
        let e = OpaqueExpr::Eq(Box::new(x()), Box::new(x()));
        let (simplified, pv) = simplifier.simplify_expr(&e);
        assert_eq!(pv, PredicateValue::AlwaysTrue);
        assert_eq!(simplified, OpaqueExpr::Const(1));
    }

    #[test]
    fn test_simplifier_simplify_expr_data_dependent() {
        let simplifier = PredicateSimplifier::new();
        let e = OpaqueExpr::Lt(Box::new(x()), Box::new(OpaqueExpr::Var("y".into())));
        let (_, pv) = simplifier.simplify_expr(&e);
        assert_eq!(pv, PredicateValue::Unknown);
    }

    #[test]
    fn test_dead_code_eliminator_mark_reachable() {
        let mut blocks: HashMap<u64, IlBasicBlock> = HashMap::new();
        let mut b0 = IlBasicBlock::new(addr(0), addr(4), 1);
        let mut b1 = IlBasicBlock::new(addr(4), addr(8), 1);
        b0.add_successor(addr(4), false);
        b0.reachable = false;
        b1.reachable = false;
        blocks.insert(0, b0);
        blocks.insert(4, b1);
        DeadCodeEliminator::mark_reachable(addr(0), &mut blocks);
        assert!(blocks[&0].reachable);
        assert!(blocks[&4].reachable);
    }

    #[test]
    fn test_dead_code_eliminator_eliminates_dead() {
        let mut blocks: HashMap<u64, IlBasicBlock> = HashMap::new();
        let mut b0 = IlBasicBlock::new(addr(0), addr(4), 1);
        let mut b1 = IlBasicBlock::new(addr(100), addr(104), 1);
        b0.reachable = true;
        b1.reachable = false;
        blocks.insert(0, b0);
        blocks.insert(100, b1);
        let removed = DeadCodeEliminator::new().eliminate(&mut blocks);
        assert_eq!(removed, 1);
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn test_dead_code_eliminator_count_dead() {
        let mut blocks = HashMap::new();
        let mut b = IlBasicBlock::new(addr(0), addr(4), 1);
        b.reachable = false;
        blocks.insert(0u64, b);
        assert_eq!(DeadCodeEliminator::count_dead(&blocks), 1);
    }

    #[test]
    fn test_il_cfg_simplify() {
        let mut cfg = IlCfg::new();
        cfg.set_entry(addr(0x1000));

        let mut b0 = IlBasicBlock::new(addr(0x1000), addr(0x1010), 4);
        b0.add_successor(addr(0x2000), true);
        b0.add_successor(addr(0x3000), true);
        cfg.add_block(b0);
        cfg.add_block(IlBasicBlock::new(addr(0x2000), addr(0x2010), 2));
        cfg.add_block(IlBasicBlock::new(addr(0x3000), addr(0x3010), 2));

        cfg.add_branch(SimpleBranch {
            address: addr(0x1000),
            condition: OpaqueExpr::Eq(Box::new(x()), Box::new(x())),
            true_target: addr(0x2000),
            false_target: addr(0x3000),
        });

        let stats = cfg.simplify();
        assert_eq!(stats.branches_simplified, 1);
    }

    #[test]
    fn test_simplification_stats_rate() {
        let stats = SimplificationStats {
            branches_simplified: 3,
            dead_blocks_removed: 1,
            total_branches: 6,
        };
        assert!((stats.simplification_rate() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_il_cfg_block_count() {
        let mut cfg = IlCfg::new();
        cfg.set_entry(addr(0));
        cfg.add_block(IlBasicBlock::new(addr(0x100), addr(0x110), 3));
        assert_eq!(cfg.block_count(), 2);
    }

    #[test]
    fn test_simplifier_apply_to_blocks_marks_dead() {
        let cfg_br = make_cfg_with_opaque();
        let mut simplifier = PredicateSimplifier::new();
        let results = simplifier.run(&cfg_br);

        let mut blocks: HashMap<u64, IlBasicBlock> = HashMap::new();
        // false_target of always-true branch (0x3000) should be marked dead.
        blocks.insert(0x3000, IlBasicBlock::new(addr(0x3000), addr(0x3010), 2));

        simplifier.apply_to_blocks(&mut blocks, &results, &cfg_br);
        assert!(!blocks[&0x3000].reachable);
    }
}
