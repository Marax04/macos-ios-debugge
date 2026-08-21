//! `opaque_rewriter` — Replace opaque predicates with unconditional control flow.
//!
//! Provides:
//! * [`OpaqueRewrite`] — description of a single branch rewrite
//! * [`RewriteResult`] — result of rewriting one function
//! * [`OpaqueRewriter`] — applies rewrites to a CFG and propagates constants
//! * Re-analysis notification for downstream passes


use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use rustre_core::address::Address;

use crate::PredicateValue;

// ─────────────────────────────────────────────────────────────────────────────
// Rewrite description
// ─────────────────────────────────────────────────────────────────────────────

/// How the conditional branch is replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RewriteKind {
    /// Replace the conditional branch with an unconditional jump to the taken target.
    AlwaysTaken,
    /// Replace the conditional branch with an unconditional jump to the fallthrough target.
    AlwaysNotTaken,
    /// The branch was opaque-false, so the entire block and its dead side are unreachable.
    DeadBlock,
}

impl std::fmt::Display for RewriteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlwaysTaken => write!(f, "AlwaysTaken"),
            Self::AlwaysNotTaken => write!(f, "AlwaysNotTaken"),
            Self::DeadBlock => write!(f, "DeadBlock"),
        }
    }
}

/// A single opaque predicate rewrite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueRewrite {
    /// Address of the conditional branch instruction that was removed.
    pub branch_address: Address,
    /// Address of the block containing the branch.
    pub block_address: Address,
    /// Which rewrite was applied.
    pub kind: RewriteKind,
    /// The target address after rewriting (always-taken or fallthrough target).
    pub resolved_target: Address,
    /// The address of the dead edge (eliminated).
    pub dead_target: Address,
    /// The predicate value that was proven.
    pub proven_value: PredicateValue,
    /// Confidence in the proof.
    pub confidence: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// CFG block model
// ─────────────────────────────────────────────────────────────────────────────

/// A simple block in the CFG used by the rewriter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriterBlock {
    /// Block address.
    pub address: Address,
    /// True branch target (taken edge).
    pub taken: Option<Address>,
    /// False branch target (not-taken / fallthrough edge).
    pub fallthrough: Option<Address>,
    /// Whether this block is unconditional (only one successor).
    pub unconditional: bool,
    /// Whether this block has been marked as dead (unreachable).
    pub is_dead: bool,
    /// Constant value of the outgoing condition, if known.
    pub known_condition: Option<bool>,
    /// Constant definitions in this block: `vreg → value`.
    pub const_defs: HashMap<u32, u64>,
    /// Number of instructions (for size heuristics).
    pub insn_count: usize,
}

impl RewriterBlock {
    #[must_use]
    pub fn new(address: Address) -> Self {
        Self {
            address,
            taken: None,
            fallthrough: None,
            unconditional: false,
            is_dead: false,
            known_condition: None,
            const_defs: HashMap::new(),
            insn_count: 0,
        }
    }

    /// Return all successor addresses.
    #[must_use]
    pub fn successors(&self) -> Vec<Address> {
        let mut s = Vec::new();
        if let Some(t) = self.taken { s.push(t); }
        if let Some(f) = self.fallthrough && !s.contains(&f) { s.push(f); }
        s
    }

    /// Whether this block has exactly two outgoing edges.
    #[must_use]
    pub fn is_conditional(&self) -> bool {
        !self.unconditional
            && self.taken.is_some()
            && self.fallthrough.is_some()
            && self.taken != self.fallthrough
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constant propagation context
// ─────────────────────────────────────────────────────────────────────────────

/// Context for intra-function constant propagation after a rewrite.
#[derive(Debug, Default)]
struct ConstPropContext {
    /// Maps block address → `vreg → constant value`.
    block_consts: HashMap<Address, HashMap<u32, u64>>,
}

impl ConstPropContext {
    fn set(&mut self, block: Address, vreg: u32, value: u64) {
        self.block_consts
            .entry(block)
            .or_default()
            .insert(vreg, value);
    }

    fn get(&self, block: Address, vreg: u32) -> Option<u64> {
        self.block_consts.get(&block)?.get(&vreg).copied()
    }

    fn merge_from(&mut self, dst: Address, src: Address) {
        if let Some(src_map) = self.block_consts.get(&src).cloned() {
            let dst_map = self.block_consts.entry(dst).or_default();
            for (vreg, val) in src_map {
                // Only keep if the value is the same as existing (meet operation)
                match dst_map.get(&vreg) {
                    None => { dst_map.insert(vreg, val); }
                    Some(&existing) if existing != val => { dst_map.remove(&vreg); }
                    _ => {}
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rewrite result
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of all rewrites applied to a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteResult {
    /// All rewrites applied.
    pub rewrites: Vec<OpaqueRewrite>,
    /// Addresses of blocks that became unreachable (dead) after rewriting.
    pub dead_blocks: Vec<Address>,
    /// How many constant values were propagated as a result of rewrites.
    pub constants_propagated: u32,
    /// Whether any change requires the caller to re-run upstream analysis passes.
    pub requires_reanalysis: bool,
    /// Whether any rewrite was applied that changed the CFG structure.
    pub cfg_changed: bool,
}

impl RewriteResult {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            rewrites: Vec::new(),
            dead_blocks: Vec::new(),
            constants_propagated: 0,
            requires_reanalysis: false,
            cfg_changed: false,
        }
    }

    #[must_use]
    pub const fn rewrite_count(&self) -> usize {
        self.rewrites.len()
    }

    #[must_use]
    pub const fn dead_block_count(&self) -> usize {
        self.dead_blocks.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Opaque predicate candidate (input to the rewriter)
// ─────────────────────────────────────────────────────────────────────────────

/// A proven opaque predicate ready to be rewritten.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenOpaquePredicate {
    /// Address of the conditional branch.
    pub branch_address: Address,
    /// Address of the block containing the branch.
    pub block_address: Address,
    /// Proven value.
    pub proven_value: PredicateValue,
    /// Taken-edge target.
    pub taken_target: Address,
    /// Fallthrough target.
    pub fallthrough_target: Address,
    /// Proof confidence.
    pub confidence: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// OpaqueRewriter
// ─────────────────────────────────────────────────────────────────────────────

/// Applies opaque predicate rewrites to a CFG.
pub struct OpaqueRewriter {
    /// Minimum confidence required to apply a rewrite.
    pub min_confidence: f32,
    /// Maximum number of dead-block removal iterations.
    pub max_dce_passes: u32,
    /// Whether to propagate constants after each rewrite.
    pub propagate_constants: bool,
}

impl Default for OpaqueRewriter {
    fn default() -> Self {
        Self {
            min_confidence: 0.60,
            max_dce_passes: 8,
            propagate_constants: true,
        }
    }
}

impl OpaqueRewriter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_min_confidence(mut self, t: f32) -> Self {
        self.min_confidence = t;
        self
    }

    #[must_use]
    pub const fn with_max_dce_passes(mut self, n: u32) -> Self {
        self.max_dce_passes = n;
        self
    }

    // ── Single predicate rewrite ──────────────────────────────────────────────

    /// Apply one opaque predicate rewrite to the CFG.
    ///
    /// Returns `None` if the confidence is below the threshold or if the block
    /// cannot be found.
    pub fn apply_one(
        &self,
        blocks: &mut HashMap<Address, RewriterBlock>,
        pred: &ProvenOpaquePredicate,
    ) -> Option<OpaqueRewrite> {
        if pred.confidence < self.min_confidence {
            return None;
        }

        let block = blocks.get_mut(&pred.block_address)?;

        if !block.is_conditional() && pred.proven_value != PredicateValue::Unknown {
            return None; // Already unconditional
        }

        let (resolved_target, dead_target, kind) = match pred.proven_value {
            PredicateValue::AlwaysTrue => (
                pred.taken_target,
                pred.fallthrough_target,
                RewriteKind::AlwaysTaken,
            ),
            PredicateValue::AlwaysFalse => (
                pred.fallthrough_target,
                pred.taken_target,
                RewriteKind::AlwaysNotTaken,
            ),
            PredicateValue::Unknown => return None,
        };

        // Update the block: make it unconditional
        block.taken = Some(resolved_target);
        block.fallthrough = None;
        block.unconditional = true;
        block.known_condition = Some(matches!(pred.proven_value, PredicateValue::AlwaysTrue));

        Some(OpaqueRewrite {
            branch_address: pred.branch_address,
            block_address: pred.block_address,
            kind,
            resolved_target,
            dead_target,
            proven_value: pred.proven_value,
            confidence: pred.confidence,
        })
    }

    // ── Dead code elimination ─────────────────────────────────────────────────

    /// Mark all blocks unreachable from `entry` as dead.
    pub fn eliminate_dead_blocks(
        &self,
        blocks: &mut HashMap<Address, RewriterBlock>,
        entry: Address,
    ) -> Vec<Address> {
        let reachable = bfs_reachable(entry, blocks);
        let all_addrs: Vec<Address> = blocks.keys().copied().collect();
        let mut dead = Vec::new();

        for addr in all_addrs {
            if !reachable.contains(&addr)
                && let Some(block) = blocks.get_mut(&addr) {
                    block.is_dead = true;
                    dead.push(addr);
                }
        }

        dead
    }

    // ── Constant propagation ──────────────────────────────────────────────────

    /// Propagate constants through the CFG after rewrites.
    ///
    /// Returns the number of new constant assignments discovered.
    pub fn propagate_constants(
        &self,
        blocks: &mut HashMap<Address, RewriterBlock>,
        entry: Address,
    ) -> u32 {
        let mut propagated = 0u32;
        let mut ctx = ConstPropContext::default();

        // Initialize with known const_defs from each block
        for (&addr, block) in blocks.iter() {
            for (&vreg, &val) in &block.const_defs {
                ctx.set(addr, vreg, val);
            }
        }

        // BFS through the CFG, propagating constants along edges
        let order = bfs_order(entry, blocks);
        for addr in &order {
            let succs: Vec<Address> = blocks
                .get(addr)
                .map(RewriterBlock::successors)
                .unwrap_or_default();

            // Propagate from this block's known constants to successors
            for succ in succs {
                let prev_count = ctx.block_consts.get(&succ).map_or(0, std::collections::HashMap::len);
                ctx.merge_from(succ, *addr);
                let new_count = ctx.block_consts.get(&succ).map_or(0, std::collections::HashMap::len);
                propagated += (new_count.saturating_sub(prev_count)) as u32;
            }
        }

        // Write discovered constants back into blocks.
        //
        // ⚠ This loop used to reach into `ctx.block_consts` directly while
        // `ConstPropContext::get` — the accessor for exactly this lookup — had
        // no caller at all and was kept alive by an `#[allow(dead_code)]`.
        // Two ways to read the same map is how the two drift apart, so the
        // write-back now goes through the accessor and `get` has the single
        // definition of "the constant proven for (block, vreg)".
        //
        // The vreg list is collected first because `get` borrows `ctx` while
        // `blocks` is borrowed mutably; the result is identical to iterating
        // the inner map.
        for (&addr, block) in blocks.iter_mut() {
            let vregs: Vec<u32> = ctx
                .block_consts
                .get(&addr)
                .map(|m| m.keys().copied().collect())
                .unwrap_or_default();
            for vreg in vregs {
                if let Some(val) = ctx.get(addr, vreg) {
                    block.const_defs.entry(vreg).or_insert(val);
                }
            }
        }

        propagated
    }

    // ── Full pipeline ─────────────────────────────────────────────────────────

    /// Apply all proven opaque predicates to the CFG.
    pub fn rewrite_all(
        &self,
        blocks: &mut HashMap<Address, RewriterBlock>,
        entry: Address,
        predicates: &[ProvenOpaquePredicate],
    ) -> RewriteResult {
        let mut result = RewriteResult::empty();

        // Sort predicates by confidence descending so highest-confidence rewrites go first
        let mut sorted: Vec<&ProvenOpaquePredicate> = predicates.iter().collect();
        sorted.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        for pred in sorted {
            if let Some(rw) = self.apply_one(blocks, pred) {
                result.cfg_changed = true;
                result.rewrites.push(rw);
            }
        }

        // DCE passes
        for _ in 0..self.max_dce_passes {
            let dead = self.eliminate_dead_blocks(blocks, entry);
            if dead.is_empty() {
                break;
            }
            result.dead_blocks.extend(dead);
        }
        result.dead_blocks.sort_unstable();
        result.dead_blocks.dedup();

        // Constant propagation
        if self.propagate_constants && result.cfg_changed {
            result.constants_propagated = self.propagate_constants(blocks, entry);
        }

        // Request re-analysis if significant changes were made
        result.requires_reanalysis = result.cfg_changed
            || !result.dead_blocks.is_empty()
            || result.constants_propagated > 0;

        result
    }

    // ── Reporting ─────────────────────────────────────────────────────────────

    /// Build a human-readable report of all rewrites.
    #[must_use]
    pub fn build_report(&self, result: &RewriteResult) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "OpaqueRewriter: {} rewrite(s), {} dead block(s), {} constant(s) propagated",
            result.rewrite_count(),
            result.dead_block_count(),
            result.constants_propagated,
        ));

        for rw in &result.rewrites {
            lines.push(format!(
                "  [{}] branch@0x{:x} in block@0x{:x} → target=0x{:x} (dead=0x{:x}) conf={:.2}",
                rw.kind,
                rw.branch_address.0,
                rw.block_address.0,
                rw.resolved_target.0,
                rw.dead_target.0,
                rw.confidence,
            ));
        }

        if !result.dead_blocks.is_empty() {
            let dead_str: Vec<String> = result
                .dead_blocks
                .iter()
                .map(|a| format!("0x{:x}", a.0))
                .collect();
            lines.push(format!("  Dead blocks: {}", dead_str.join(", ")));
        }

        if result.requires_reanalysis {
            lines.push("  [!] Requires re-analysis of dependent passes.".into());
        }

        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn bfs_reachable(
    start: Address,
    blocks: &HashMap<Address, RewriterBlock>,
) -> HashSet<Address> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(start);
    visited.insert(start);

    while let Some(addr) = queue.pop_front() {
        if let Some(block) = blocks.get(&addr) {
            for succ in block.successors() {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
    }

    visited
}

fn bfs_order(
    start: Address,
    blocks: &HashMap<Address, RewriterBlock>,
) -> Vec<Address> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut order = Vec::new();

    queue.push_back(start);
    visited.insert(start);

    while let Some(addr) = queue.pop_front() {
        order.push(addr);
        if let Some(block) = blocks.get(&addr) {
            for succ in block.successors() {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
    }

    order
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

    fn make_conditional_block(address: Address, taken: Address, fallthrough: Address) -> RewriterBlock {
        let mut b = RewriterBlock::new(address);
        b.taken = Some(taken);
        b.fallthrough = Some(fallthrough);
        b.unconditional = false;
        b
    }

    fn make_unconditional_block(address: Address, target: Address) -> RewriterBlock {
        let mut b = RewriterBlock::new(address);
        b.taken = Some(target);
        b.unconditional = true;
        b
    }

    fn make_terminal_block(address: Address) -> RewriterBlock {
        RewriterBlock::new(address)
    }

    fn build_simple_cfg() -> (HashMap<Address, RewriterBlock>, Address) {
        // entry → [cond_block] → taken_block OR dead_block
        let entry = addr(0x100);
        let cond = addr(0x200);
        let taken = addr(0x300);
        let dead = addr(0x400);
        let exit = addr(0x500);

        let mut blocks = HashMap::new();
        blocks.insert(entry, make_unconditional_block(entry, cond));
        blocks.insert(cond, make_conditional_block(cond, taken, dead));
        blocks.insert(taken, make_unconditional_block(taken, exit));
        blocks.insert(dead, make_terminal_block(dead));
        blocks.insert(exit, make_terminal_block(exit));

        (blocks, entry)
    }

    #[test]
    fn test_apply_one_always_true() {
        let rewriter = OpaqueRewriter::new().with_min_confidence(0.5);
        let (mut blocks, _entry) = build_simple_cfg();

        let pred = ProvenOpaquePredicate {
            branch_address: addr(0x210),
            block_address: addr(0x200),
            proven_value: PredicateValue::AlwaysTrue,
            taken_target: addr(0x300),
            fallthrough_target: addr(0x400),
            confidence: 0.90,
        };

        let rw = rewriter.apply_one(&mut blocks, &pred);
        assert!(rw.is_some());
        let rw = rw.unwrap();
        assert_eq!(rw.kind, RewriteKind::AlwaysTaken);
        assert_eq!(rw.resolved_target, addr(0x300));
        assert_eq!(rw.dead_target, addr(0x400));

        // Block should now be unconditional
        let block = &blocks[&addr(0x200)];
        assert!(block.unconditional);
        assert_eq!(block.taken, Some(addr(0x300)));
        assert_eq!(block.fallthrough, None);
    }

    #[test]
    fn test_apply_one_always_false() {
        let rewriter = OpaqueRewriter::new().with_min_confidence(0.5);
        let (mut blocks, _) = build_simple_cfg();

        let pred = ProvenOpaquePredicate {
            branch_address: addr(0x210),
            block_address: addr(0x200),
            proven_value: PredicateValue::AlwaysFalse,
            taken_target: addr(0x300),
            fallthrough_target: addr(0x400),
            confidence: 0.85,
        };

        let rw = rewriter.apply_one(&mut blocks, &pred).unwrap();
        assert_eq!(rw.kind, RewriteKind::AlwaysNotTaken);
        assert_eq!(rw.resolved_target, addr(0x400));
    }

    #[test]
    fn test_apply_one_low_confidence_rejected() {
        let rewriter = OpaqueRewriter::new().with_min_confidence(0.80);
        let (mut blocks, _) = build_simple_cfg();

        let pred = ProvenOpaquePredicate {
            branch_address: addr(0x210),
            block_address: addr(0x200),
            proven_value: PredicateValue::AlwaysTrue,
            taken_target: addr(0x300),
            fallthrough_target: addr(0x400),
            confidence: 0.50, // below threshold
        };

        let rw = rewriter.apply_one(&mut blocks, &pred);
        assert!(rw.is_none());
    }

    #[test]
    fn test_eliminate_dead_blocks() {
        let rewriter = OpaqueRewriter::new();
        let (mut blocks, entry) = build_simple_cfg();

        // Make cond block unconditional → dead block 0x400 becomes unreachable
        blocks.get_mut(&addr(0x200)).unwrap().unconditional = true;
        blocks.get_mut(&addr(0x200)).unwrap().fallthrough = None;

        let dead = rewriter.eliminate_dead_blocks(&mut blocks, entry);
        assert!(dead.contains(&addr(0x400)));
        assert!(blocks[&addr(0x400)].is_dead);
    }

    #[test]
    fn test_rewrite_all_pipeline() {
        let rewriter = OpaqueRewriter::new().with_min_confidence(0.5);
        let (mut blocks, entry) = build_simple_cfg();

        let predicates = vec![ProvenOpaquePredicate {
            branch_address: addr(0x210),
            block_address: addr(0x200),
            proven_value: PredicateValue::AlwaysTrue,
            taken_target: addr(0x300),
            fallthrough_target: addr(0x400),
            confidence: 0.95,
        }];

        let result = rewriter.rewrite_all(&mut blocks, entry, &predicates);
        assert!(result.cfg_changed);
        assert_eq!(result.rewrite_count(), 1);
        // 0x400 should be dead after rewrite
        assert!(result.dead_blocks.contains(&addr(0x400)));
    }

    #[test]
    fn test_build_report_non_empty() {
        let rewriter = OpaqueRewriter::new();
        let result = RewriteResult {
            rewrites: vec![OpaqueRewrite {
                branch_address: addr(0x210),
                block_address: addr(0x200),
                kind: RewriteKind::AlwaysTaken,
                resolved_target: addr(0x300),
                dead_target: addr(0x400),
                proven_value: PredicateValue::AlwaysTrue,
                confidence: 0.90,
            }],
            dead_blocks: vec![addr(0x400)],
            constants_propagated: 3,
            requires_reanalysis: true,
            cfg_changed: true,
        };
        let report = rewriter.build_report(&result);
        assert!(report.contains("1 rewrite(s)"));
        assert!(report.contains("AlwaysTaken"));
    }

    #[test]
    fn test_propagate_constants() {
        let rewriter = OpaqueRewriter::new();
        let entry = addr(0x100);
        let exit = addr(0x200);

        let mut b_entry = RewriterBlock::new(entry);
        b_entry.taken = Some(exit);
        b_entry.unconditional = true;
        b_entry.const_defs.insert(0, 42); // vreg 0 = 42

        let b_exit = RewriterBlock::new(exit);

        let mut blocks = HashMap::new();
        blocks.insert(entry, b_entry);
        blocks.insert(exit, b_exit);

        let propagated = rewriter.propagate_constants(&mut blocks, entry);
        assert!(propagated >= 1);
        // vreg 0 should now be known in the exit block
        assert_eq!(blocks[&exit].const_defs.get(&0), Some(&42));
    }
}
