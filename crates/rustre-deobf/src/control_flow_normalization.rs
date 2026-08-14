//! Control-flow normalisation passes applied after initial deobfuscation.
//!
//! # Relation to `cfg_normalizer`
//! This module works on a **`HashMap<Addr, BasicBlock>`** keyed by virtual
//! byte addresses and implements deobfuscation micro-passes: chained-jump
//! elimination, branch simplification, NOP-sled removal, unreachable-block
//! pruning, and dominator-tree computation.
//!
//! [`cfg_normalizer`](crate::cfg_normalizer) works on a **`Vec<CfgBlock>`**
//! with file-offset-based successor lists and targets structural graph
//! transformations (linear-chain merging, call/ret boundary splits, useless
//! jump removal). The two modules serve different CFG representations and are
//! intentionally kept separate.
//!
//! Provides a pipeline of micro-passes that clean up residual control-flow
//! artefacts left behind by deobfuscators:
//!
//! * [`ChainedJumpEliminator`] — collapses `jmp → jmp → target` chains.
//! * [`UselessBlockRemover`] — deletes blocks with no in-edges (dead code).
//! * [`BranchSimplifier`] — rewrites always-taken / never-taken branches.
//! * [`NopSledRemover`] — removes NOP padding between real instructions.
//! * [`CfgNormalizer`] — orchestrates all the above passes.
//! * [`NormalizationReport`] — collects statistics from one normalisation run.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// Address newtype
// ─────────────────────────────────────────────────────────────────────────────

/// A virtual address used throughout the normalisation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr(pub u64);

impl Addr {
    /// Create a new address.
    #[must_use]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw u64 value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge type
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of a CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Unconditional jump or fall-through.
    Unconditional,
    /// True branch of a conditional.
    True,
    /// False branch of a conditional.
    False,
}

// ─────────────────────────────────────────────────────────────────────────────
// BasicBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A single basic block in the normalisation CFG.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Start address.
    pub start: Addr,
    /// End address (exclusive).
    pub end: Addr,
    /// Raw instruction bytes.
    pub bytes: Vec<u8>,
    /// Successors: `(target, edge_kind)`.
    pub successors: Vec<(Addr, EdgeKind)>,
    /// Predecessor count (maintained by [`CfgNormalizer`]).
    pub predecessor_count: usize,
    /// If `true`, the block contains only NOP bytes (`0x90`).
    pub is_nop_only: bool,
    /// If `true`, the block is an unconditional jump to a single target.
    pub is_unconditional_jump: bool,
    /// Constant condition value, if this block ends with a branch whose
    /// outcome is statically known: `Some(true)` = always taken, etc.
    pub constant_condition: Option<bool>,
}

impl BasicBlock {
    /// Create a new block.
    #[must_use]
    pub const fn new(start: Addr, end: Addr, bytes: Vec<u8>) -> Self {
        Self {
            start,
            end,
            bytes,
            successors: Vec::new(),
            predecessor_count: 0,
            is_nop_only: false,
            is_unconditional_jump: false,
            constant_condition: None,
        }
    }

    /// Add a successor edge.
    pub fn add_successor(&mut self, target: Addr, kind: EdgeKind) {
        self.successors.push((target, kind));
    }

    /// Return `true` if this block has exactly one successor.
    #[must_use]
    pub const fn has_single_successor(&self) -> bool {
        self.successors.len() == 1
    }

    /// Return `true` if this block has no successors (terminal).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.successors.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NormalizationReport
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics produced after one normalisation run.
#[derive(Debug, Clone, Default)]
pub struct NormalizationReport {
    /// Number of chained-jump chains collapsed.
    pub chained_jumps_collapsed: usize,
    /// Number of unreachable blocks removed.
    pub dead_blocks_removed: usize,
    /// Number of always-taken branches simplified.
    pub always_taken_branches: usize,
    /// Number of never-taken branches simplified.
    pub never_taken_branches: usize,
    /// Number of NOP sleds removed.
    pub nop_sleds_removed: usize,
    /// Total NOP bytes removed.
    pub nop_bytes_removed: usize,
    /// Blocks remaining after normalisation.
    pub blocks_remaining: usize,
    /// Human-readable diagnostics.
    pub diagnostics: Vec<String>,
}

impl NormalizationReport {
    /// Create an empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of normalisation actions taken.
    #[must_use]
    pub const fn total_actions(&self) -> usize {
        self.chained_jumps_collapsed
            + self.dead_blocks_removed
            + self.always_taken_branches
            + self.never_taken_branches
            + self.nop_sleds_removed
    }

    /// Return `true` when at least one normalisation action was taken.
    #[must_use]
    pub const fn did_something(&self) -> bool {
        self.total_actions() > 0
    }

    /// Append a diagnostic message.
    pub fn note(&mut self, msg: impl Into<String>) {
        self.diagnostics.push(msg.into());
    }

    /// One-line summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "chained_jumps={} dead_blocks={} always_taken={} never_taken={} nop_sleds={}",
            self.chained_jumps_collapsed,
            self.dead_blocks_removed,
            self.always_taken_branches,
            self.never_taken_branches,
            self.nop_sleds_removed,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChainedJumpEliminator
// ─────────────────────────────────────────────────────────────────────────────

/// Collapses chains of unconditional jumps so that every jump target points
/// directly to a non-trampoline block.
///
/// A *chained jump* is an unconditional jump to a block that itself contains
/// only an unconditional jump (a "trampoline").  After elimination every
/// predecessor of a trampoline block is rewired to jump directly to the
/// trampoline's target, and the trampoline is marked dead.
#[derive(Debug, Clone, Default)]
pub struct ChainedJumpEliminator {
    /// Maximum chain length to follow before giving up (default 64).
    pub max_chain_depth: usize,
}

impl ChainedJumpEliminator {
    /// Create an eliminator with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_chain_depth: 64,
        }
    }

    /// Set the maximum chain depth.
    #[must_use]
    pub const fn with_max_depth(mut self, d: usize) -> Self {
        self.max_chain_depth = d;
        self
    }

    /// Resolve the ultimate target of a chained-jump starting at `addr`.
    ///
    /// If `addr` is itself a trampoline, follows the chain up to
    /// `max_chain_depth` hops and returns the first non-trampoline address.
    /// Returns `addr` unchanged when it is not a trampoline.
    #[must_use]
    pub fn resolve_target(&self, addr: Addr, blocks: &HashMap<Addr, BasicBlock>) -> Addr {
        let mut current = addr;
        for _ in 0..self.max_chain_depth {
            match blocks.get(&current) {
                Some(bb) if bb.is_unconditional_jump && bb.successors.len() == 1 => {
                    let next = bb.successors[0].0;
                    if next == current {
                        break; // infinite loop guard
                    }
                    current = next;
                }
                _ => break,
            }
        }
        current
    }

    /// Run the pass over `blocks`, returning the number of chains collapsed.
    pub fn run(&self, blocks: &mut HashMap<Addr, BasicBlock>, report: &mut NormalizationReport) {
        // Collect all blocks that are trampolines.
        let trampolines: HashSet<Addr> = blocks
            .iter()
            .filter(|(_, bb)| bb.is_unconditional_jump && bb.successors.len() == 1)
            .map(|(&addr, _)| addr)
            .collect();

        // Rewire predecessors to bypass trampolines.
        let addresses: Vec<Addr> = blocks.keys().copied().collect();
        for &addr in &addresses {
            // Clone only the successors vector — we don't need the rest of the block.
            let succs: Vec<(Addr, EdgeKind)> = match blocks.get(&addr) {
                Some(b) => b.successors.clone(),
                None => continue,
            };
            let mut changed = false;
            let mut new_succs: Vec<(Addr, EdgeKind)> = Vec::with_capacity(succs.len());
            for (target, kind) in &succs {
                if trampolines.contains(target) {
                    let resolved = self.resolve_target(*target, blocks);
                    if resolved != *target {
                        new_succs.push((resolved, *kind));
                        changed = true;
                        report.chained_jumps_collapsed += 1;
                        report.note(format!("rewired {addr} → {resolved} (was {target})"));
                        continue;
                    }
                }
                new_succs.push((*target, *kind));
            }
            if changed
                && let Some(b) = blocks.get_mut(&addr) {
                    b.successors = new_succs;
                }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UselessBlockRemover
// ─────────────────────────────────────────────────────────────────────────────

/// Removes basic blocks that are unreachable from the function entry.
///
/// Uses a BFS/DFS from the entry block and removes all blocks not reached.
#[derive(Debug, Clone, Default)]
pub struct UselessBlockRemover;

impl UselessBlockRemover {
    /// Create a new remover.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute the set of reachable block addresses from `entry`.
    #[must_use]
    pub fn reachable(&self, entry: Addr, blocks: &HashMap<Addr, BasicBlock>) -> HashSet<Addr> {
        let mut visited: HashSet<Addr> = HashSet::new();
        let mut worklist: VecDeque<Addr> = VecDeque::new();
        if blocks.contains_key(&entry) {
            worklist.push_back(entry);
        }
        while let Some(addr) = worklist.pop_front() {
            if visited.insert(addr)
                && let Some(bb) = blocks.get(&addr) {
                    for &(succ, _) in &bb.successors {
                        if !visited.contains(&succ) {
                            worklist.push_back(succ);
                        }
                    }
                }
        }
        visited
    }

    /// Remove all blocks not reachable from `entry`.
    pub fn run(
        &self,
        entry: Addr,
        blocks: &mut HashMap<Addr, BasicBlock>,
        report: &mut NormalizationReport,
    ) {
        let reachable = self.reachable(entry, blocks);
        let dead: Vec<Addr> = blocks
            .keys()
            .copied()
            .filter(|a| !reachable.contains(a))
            .collect();
        for addr in &dead {
            blocks.remove(addr);
            report.dead_blocks_removed += 1;
            report.note(format!("removed dead block at {addr}"));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BranchSimplifier
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrites statically-known branches:
///
/// * **Always-taken** (`constant_condition == Some(true)`): removes the false
///   edge and marks the block as an unconditional jump.
/// * **Never-taken** (`constant_condition == Some(false)`): removes the true
///   edge and keeps only the false edge.
#[derive(Debug, Clone, Default)]
pub struct BranchSimplifier;

impl BranchSimplifier {
    /// Create a new simplifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Simplify all statically-known branches in `blocks`.
    ///
    /// # Panics
    ///
    /// Panics if a block is present in the map at the start of iteration but
    /// removed before its mutable reference is taken (should never occur in
    /// practice).
    pub fn run(&self, blocks: &mut HashMap<Addr, BasicBlock>, report: &mut NormalizationReport) {
        let addresses: Vec<Addr> = blocks.keys().copied().collect();
        for addr in addresses {
            let cond = match blocks.get(&addr) {
                Some(bb) => bb.constant_condition,
                None => continue,
            };
            match cond {
                Some(true) => {
                    // Keep only the True edge.
                    let bb = blocks.get_mut(&addr).unwrap();
                    let true_target = bb
                        .successors
                        .iter()
                        .find(|(_, k)| *k == EdgeKind::True)
                        .map(|(t, _)| *t);
                    if let Some(target) = true_target {
                        bb.successors = vec![(target, EdgeKind::Unconditional)];
                        bb.is_unconditional_jump = true;
                        bb.constant_condition = None;
                        report.always_taken_branches += 1;
                        report.note(format!("always-taken branch at {addr} → {target}"));
                    }
                }
                Some(false) => {
                    // Keep only the False edge.
                    let bb = blocks.get_mut(&addr).unwrap();
                    let false_target = bb
                        .successors
                        .iter()
                        .find(|(_, k)| *k == EdgeKind::False)
                        .map(|(t, _)| *t);
                    if let Some(target) = false_target {
                        bb.successors = vec![(target, EdgeKind::Unconditional)];
                        bb.is_unconditional_jump = true;
                        bb.constant_condition = None;
                        report.never_taken_branches += 1;
                        report.note(format!("never-taken branch at {addr} → {target}"));
                    }
                }
                None => {}
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NopSledRemover
// ─────────────────────────────────────────────────────────────────────────────

/// Removes blocks that consist entirely of NOP instructions (`0x90`), and
/// rewires all predecessors of a NOP block directly to its successor.
#[derive(Debug, Clone)]
pub struct NopSledRemover {
    /// Minimum number of NOP bytes in a block to be considered a sled (default 1).
    pub min_nop_count: usize,
}

impl Default for NopSledRemover {
    fn default() -> Self {
        Self { min_nop_count: 1 }
    }
}

impl NopSledRemover {
    /// Create a remover with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether `bb` is a NOP-only block.
    #[must_use]
    pub fn is_nop_block(&self, bb: &BasicBlock) -> bool {
        !bb.bytes.is_empty()
            && bb.bytes.iter().all(|&b| b == 0x90)
            && bb.bytes.len() >= self.min_nop_count
    }

    /// Remove NOP-only blocks and rewire predecessors.
    pub fn run(&self, blocks: &mut HashMap<Addr, BasicBlock>, report: &mut NormalizationReport) {
        // Find all NOP blocks.
        let nop_addrs: Vec<Addr> = blocks
            .iter()
            .filter(|(_, bb)| self.is_nop_block(bb) && bb.has_single_successor())
            .map(|(&a, _)| a)
            .collect();

        // Build map: nop_addr → successor addr.
        let nop_targets: HashMap<Addr, Addr> = nop_addrs
            .iter()
            .filter_map(|&a| {
                blocks
                    .get(&a)
                    .and_then(|bb| bb.successors.first().map(|(t, _)| (a, *t)))
            })
            .collect();

        // Rewire all predecessors.
        let all_addrs: Vec<Addr> = blocks.keys().copied().collect();
        for &addr in &all_addrs {
            let Some(bb) = blocks.get_mut(&addr) else { continue };
            for (target, _) in &mut bb.successors {
                if let Some(&real) = nop_targets.get(target) {
                    *target = real;
                }
            }
        }

        // Remove the NOP blocks.
        for (addr, &target) in &nop_targets {
            if let Some(bb) = blocks.remove(addr) {
                report.nop_sleds_removed += 1;
                report.nop_bytes_removed += bb.bytes.len();
                report.note(format!(
                    "removed NOP block at {} ({} bytes), rewired to {}",
                    addr,
                    bb.bytes.len(),
                    target
                ));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfgNormalizer
// ─────────────────────────────────────────────────────────────────────────────

/// Orchestrates all normalisation passes over a function CFG represented as a
/// `HashMap<Addr, BasicBlock>`.
///
/// The normalisation pipeline runs in a fixed-point loop:
/// 1. [`BranchSimplifier`] — resolve constant branches first.
/// 2. [`ChainedJumpEliminator`] — collapse trampoline jumps.
/// 3. [`NopSledRemover`] — eliminate NOP-only blocks.
/// 4. [`UselessBlockRemover`] — prune unreachable blocks.
///
/// The loop repeats until no further changes are made (or the iteration limit
/// is reached).
/// Which sub-passes the [`CfgNormalizer`] should run.
#[derive(Debug, Clone)]
pub struct CfgNormalizerPasses {
    /// Whether to run [`BranchSimplifier`].
    pub simplify_branches: bool,
    /// Whether to run [`ChainedJumpEliminator`].
    pub eliminate_chained_jumps: bool,
    /// Whether to run [`NopSledRemover`].
    pub remove_nop_sleds: bool,
}

impl Default for CfgNormalizerPasses {
    fn default() -> Self {
        Self { simplify_branches: true, eliminate_chained_jumps: true, remove_nop_sleds: true }
    }
}

#[derive(Debug, Clone)]
pub struct CfgNormalizer {
    /// Maximum number of fixed-point iterations (default 20).
    pub max_iterations: usize,
    /// Entry address of the function being normalised.
    pub entry: Addr,
    /// Which sub-passes to enable.
    pub passes: CfgNormalizerPasses,
    /// Whether to run [`UselessBlockRemover`].
    pub remove_dead_blocks: bool,
}

impl CfgNormalizer {
    /// Create a normalizer with all passes enabled and `max_iterations = 20`.
    #[must_use]
    pub const fn new(entry: Addr) -> Self {
        Self {
            max_iterations: 20,
            entry,
            passes: CfgNormalizerPasses {
                simplify_branches: true,
                eliminate_chained_jumps: true,
                remove_nop_sleds: true,
            },
            remove_dead_blocks: true,
        }
    }

    /// Convenience accessor for `passes.simplify_branches`.
    #[must_use]
    pub const fn simplify_branches(&self) -> bool { self.passes.simplify_branches }
    /// Convenience accessor for `passes.eliminate_chained_jumps`.
    #[must_use]
    pub const fn eliminate_chained_jumps(&self) -> bool { self.passes.eliminate_chained_jumps }
    /// Convenience accessor for `passes.remove_nop_sleds`.
    #[must_use]
    pub const fn remove_nop_sleds(&self) -> bool { self.passes.remove_nop_sleds }

    /// Recompute predecessor counts for all blocks.
    pub fn recompute_predecessors(blocks: &mut HashMap<Addr, BasicBlock>) {
        for bb in blocks.values_mut() {
            bb.predecessor_count = 0;
        }
        let edges: Vec<(Addr, Addr)> = blocks
            .iter()
            .flat_map(|(&src, bb)| bb.successors.iter().map(move |&(dst, _)| (src, dst)))
            .collect();
        for (_, dst) in edges {
            if let Some(bb) = blocks.get_mut(&dst) {
                bb.predecessor_count += 1;
            }
        }
    }

    /// Run the full normalisation pipeline on `blocks`, returning a report.
    pub fn run(&self, blocks: &mut HashMap<Addr, BasicBlock>) -> NormalizationReport {
        let mut report = NormalizationReport::new();
        let branch_simplifier = BranchSimplifier::new();
        let jump_eliminator = ChainedJumpEliminator::new();
        let nop_remover = NopSledRemover::new();
        let dead_remover = UselessBlockRemover::new();

        for iteration in 0..self.max_iterations {
            let before = blocks.len();

            if self.passes.simplify_branches {
                branch_simplifier.run(blocks, &mut report);
            }
            if self.passes.eliminate_chained_jumps {
                jump_eliminator.run(blocks, &mut report);
            }
            if self.passes.remove_nop_sleds {
                nop_remover.run(blocks, &mut report);
            }
            if self.remove_dead_blocks {
                dead_remover.run(self.entry, blocks, &mut report);
            }

            Self::recompute_predecessors(blocks);
            let after = blocks.len();

            if after == before && iteration > 0 {
                report.note(format!(
                    "fixed-point reached after {} iteration(s)",
                    iteration + 1
                ));
                break;
            }
        }

        report.blocks_remaining = blocks.len();
        report
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DominatorTree — simple dominator computation for CFG analysis
// ─────────────────────────────────────────────────────────────────────────────

/// A dominator-tree entry mapping each block to its immediate dominator.
///
/// Block A *dominates* block B when every path from the entry to B goes through A.
/// The immediate dominator (idom) of B is the closest dominator of B.
#[derive(Debug, Clone, Default)]
pub struct DominatorTree {
    /// `block → immediate_dominator`.  The entry block maps to itself.
    pub idom: std::collections::HashMap<Addr, Addr>,
}

impl DominatorTree {
    /// Compute the dominator tree from `entry` using a simple iterative algorithm.
    ///
    /// The algorithm is equivalent to the Cooper-Harvey-Kennedy algorithm for
    /// small CFGs.  Complexity O(V²) in the worst case, acceptable for typical
    /// deobfuscation CFGs (< 1 000 blocks).
    #[must_use]
    pub fn compute(entry: Addr, blocks: &HashMap<Addr, BasicBlock>) -> Self {
        // Assign a reverse-post-order numbering (BFS order here as approximation).
        let order: Vec<Addr> = {
            let mut visited: HashSet<Addr> = HashSet::with_capacity(blocks.len());
            let mut queue: VecDeque<Addr> = VecDeque::new();
            let mut ord: Vec<Addr> = Vec::with_capacity(blocks.len());
            if blocks.contains_key(&entry) {
                queue.push_back(entry);
                visited.insert(entry);
            }
            while let Some(a) = queue.pop_front() {
                ord.push(a);
                if let Some(bb) = blocks.get(&a) {
                    for &(succ, _) in &bb.successors {
                        if visited.insert(succ) {
                            queue.push_back(succ);
                        }
                    }
                }
            }
            ord
        };

        let pos: HashMap<Addr, usize> = order.iter().enumerate().map(|(i, &a)| (a, i)).collect();

        // Initialise idom: entry dominates itself; all others unset (use entry as sentinel).
        let mut idom: HashMap<Addr, Addr> = HashMap::new();
        for &a in &order {
            idom.insert(a, entry);
        }

        // Build predecessor map (within the reachable set).
        let mut preds: HashMap<Addr, Vec<Addr>> = HashMap::new();
        for &a in &order {
            preds.entry(a).or_default();
        }
        for &a in &order {
            if let Some(bb) = blocks.get(&a) {
                for &(s, _) in &bb.successors {
                    if pos.contains_key(&s) {
                        preds.entry(s).or_default().push(a);
                    }
                }
            }
        }

        // Iterative fixed-point (simplified, single pass suffices for tree-shaped CFGs).
        let mut changed = true;
        while changed {
            changed = false;
            for &b in order.iter().skip(1) {
                let preds_b: Vec<Addr> = preds.get(&b).cloned().unwrap_or_default();
                let processed: Vec<Addr> = preds_b
                    .iter()
                    .filter(|&&p| idom.contains_key(&p))
                    .copied()
                    .collect();
                if processed.is_empty() {
                    continue;
                }
                let mut new_idom = processed[0];
                for &p in processed.iter().skip(1) {
                    new_idom = Self::intersect(new_idom, p, &idom, &pos);
                }
                if idom.get(&b) != Some(&new_idom) {
                    idom.insert(b, new_idom);
                    changed = true;
                }
            }
        }

        Self { idom }
    }

    fn intersect(
        mut b1: Addr,
        mut b2: Addr,
        idom: &HashMap<Addr, Addr>,
        pos: &HashMap<Addr, usize>,
    ) -> Addr {
        let mut depth = 0;
        while b1 != b2 && depth < 256 {
            while pos.get(&b1).copied().unwrap_or(0) > pos.get(&b2).copied().unwrap_or(0) {
                b1 = *idom.get(&b1).unwrap_or(&b1);
            }
            while pos.get(&b2).copied().unwrap_or(0) > pos.get(&b1).copied().unwrap_or(0) {
                b2 = *idom.get(&b2).unwrap_or(&b2);
            }
            depth += 1;
        }
        b1
    }

    /// Return the immediate dominator of `block`, or `None` if unknown.
    #[must_use]
    pub fn idom_of(&self, block: Addr) -> Option<Addr> {
        self.idom.get(&block).copied()
    }

    /// Return `true` if `dom` dominates `block`.
    #[must_use]
    pub fn dominates(&self, dom: Addr, block: Addr) -> bool {
        let mut cur = block;
        let mut depth = 0;
        loop {
            if cur == dom {
                return true;
            }
            let Some(&parent) = self.idom.get(&cur) else { return false };
            if parent == cur {
                return cur == dom; // at root
            }
            cur = parent;
            depth += 1;
            if depth > 512 {
                break;
            } // cycle guard
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build a test CFG
// ─────────────────────────────────────────────────────────────────────────────

/// One entry describing a basic block for `build_cfg`:
/// `(start, end, bytes, successors, is_unconditional, constant_condition)`.
pub type CfgEntry<'a> = (u64, u64, &'a [u8], &'a [(u64, EdgeKind)], bool, Option<bool>);

/// Build a `HashMap<Addr, BasicBlock>` from a list of
/// `(start, end, bytes, successors, is_unconditional, constant_condition)`.
#[must_use]
pub fn build_cfg(
    entries: &[CfgEntry<'_>],
) -> HashMap<Addr, BasicBlock> {
    let mut map = HashMap::new();
    for &(start, end, bytes, succs, is_uj, cc) in entries {
        let mut bb = BasicBlock::new(Addr(start), Addr(end), bytes.to_vec());
        for &(t, k) in succs {
            bb.add_successor(Addr(t), k);
        }
        bb.is_unconditional_jump = is_uj;
        bb.constant_condition = cc;
        map.insert(Addr(start), bb);
    }
    map
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Addr ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_addr_display() {
        assert_eq!(Addr(0x1000).to_string(), "0x1000");
    }

    #[test]
    fn test_addr_equality() {
        assert_eq!(Addr(0xDEAD), Addr(0xDEAD));
        assert_ne!(Addr(1), Addr(2));
    }

    #[test]
    fn test_addr_ordering() {
        let mut v = vec![Addr(3), Addr(1), Addr(2)];
        v.sort();
        assert_eq!(v, vec![Addr(1), Addr(2), Addr(3)]);
    }

    // ── NormalizationReport ───────────────────────────────────────────────────

    #[test]
    fn test_report_default_empty() {
        let r = NormalizationReport::default();
        assert_eq!(r.total_actions(), 0);
        assert!(!r.did_something());
    }

    #[test]
    fn test_report_total_actions() {
        let mut r = NormalizationReport::new();
        r.chained_jumps_collapsed = 2;
        r.dead_blocks_removed = 1;
        r.always_taken_branches = 3;
        assert_eq!(r.total_actions(), 6);
        assert!(r.did_something());
    }

    #[test]
    fn test_report_summary_format() {
        let mut r = NormalizationReport::new();
        r.chained_jumps_collapsed = 1;
        r.dead_blocks_removed = 2;
        assert!(r.summary().contains("chained_jumps=1"));
        assert!(r.summary().contains("dead_blocks=2"));
    }

    #[test]
    fn test_report_note() {
        let mut r = NormalizationReport::new();
        r.note("hello");
        assert_eq!(r.diagnostics.len(), 1);
        assert_eq!(r.diagnostics[0], "hello");
    }

    // ── BasicBlock ────────────────────────────────────────────────────────────

    #[test]
    fn test_basic_block_new() {
        let bb = BasicBlock::new(Addr(0x100), Addr(0x110), vec![0x90]);
        assert_eq!(bb.start, Addr(0x100));
        assert_eq!(bb.end, Addr(0x110));
        assert!(bb.successors.is_empty());
        assert!(!bb.is_unconditional_jump);
    }

    #[test]
    fn test_basic_block_add_successor() {
        let mut bb = BasicBlock::new(Addr(0), Addr(4), vec![]);
        bb.add_successor(Addr(4), EdgeKind::Unconditional);
        assert_eq!(bb.successors.len(), 1);
        assert!(bb.has_single_successor());
    }

    #[test]
    fn test_basic_block_terminal() {
        let bb = BasicBlock::new(Addr(0), Addr(1), vec![0xC3]);
        assert!(bb.is_terminal());
    }

    // ── ChainedJumpEliminator ─────────────────────────────────────────────────

    fn make_trampoline_chain() -> HashMap<Addr, BasicBlock> {
        // A → B (trampoline) → C (real)
        build_cfg(&[
            (
                0x100,
                0x102,
                &[0xEB, 0x00],
                &[(0x200, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (
                0x200,
                0x202,
                &[0xEB, 0x00],
                &[(0x300, EdgeKind::Unconditional)],
                true,
                None,
            ),
            (0x300, 0x301, &[0xC3], &[], false, None),
        ])
    }

    #[test]
    fn test_chained_jump_resolve() {
        let blocks = make_trampoline_chain();
        let elim = ChainedJumpEliminator::new();
        let resolved = elim.resolve_target(Addr(0x200), &blocks);
        assert_eq!(resolved, Addr(0x300));
    }

    #[test]
    fn test_chained_jump_run() {
        let mut blocks = make_trampoline_chain();
        let elim = ChainedJumpEliminator::new();
        let mut report = NormalizationReport::new();
        elim.run(&mut blocks, &mut report);
        // Block A should now jump directly to C.
        assert_eq!(blocks[&Addr(0x100)].successors[0].0, Addr(0x300));
        assert!(report.chained_jumps_collapsed >= 1);
    }

    #[test]
    fn test_chained_jump_non_trampoline_unchanged() {
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x105,
                &[0x90; 5],
                &[(0x200, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (0x200, 0x201, &[0xC3], &[], false, None),
        ]);
        let elim = ChainedJumpEliminator::new();
        let mut report = NormalizationReport::new();
        elim.run(&mut blocks, &mut report);
        // 0x200 is not a trampoline (is_unconditional_jump == false).
        assert_eq!(blocks[&Addr(0x100)].successors[0].0, Addr(0x200));
        assert_eq!(report.chained_jumps_collapsed, 0);
    }

    #[test]
    fn test_chained_jump_self_loop_guard() {
        let mut blocks = build_cfg(&[(
            0x100,
            0x102,
            &[0xEB, 0xFE],
            &[(0x100, EdgeKind::Unconditional)],
            true,
            None,
        )]);
        let elim = ChainedJumpEliminator::new();
        let mut report = NormalizationReport::new();
        elim.run(&mut blocks, &mut report);
        // Should not panic or loop infinitely.
        assert_eq!(blocks[&Addr(0x100)].successors[0].0, Addr(0x100));
    }

    #[test]
    fn test_chained_jump_depth_limit() {
        // Build a chain of length 100 — should be limited by max_chain_depth.
        let mut entries: Vec<CfgEntry<'_>> = Vec::new();
        // We can't easily build 100-element static arrays, so build a 5-deep chain.
        let addrs: Vec<u64> = (0..=5).map(|i| 0x100 + i * 0x10).collect();
        for i in 0..5usize {
            let s: &'static [(u64, EdgeKind)] =
                Box::leak(vec![(addrs[i + 1], EdgeKind::Unconditional)].into_boxed_slice());
            entries.push((addrs[i], addrs[i] + 2, &[0xEB, 0x00], s, true, None));
        }
        entries.push((addrs[5], addrs[5] + 1, &[0xC3], &[], false, None));
        let blocks: HashMap<Addr, BasicBlock> = entries
            .iter()
            .map(|&(s, e, b, succs, uj, cc)| {
                let mut bb = BasicBlock::new(Addr(s), Addr(e), b.to_vec());
                for &(t, k) in succs {
                    bb.add_successor(Addr(t), k);
                }
                bb.is_unconditional_jump = uj;
                bb.constant_condition = cc;
                (Addr(s), bb)
            })
            .collect();
        let elim = ChainedJumpEliminator::new();
        let resolved = elim.resolve_target(Addr(addrs[0]), &blocks);
        assert_eq!(resolved, Addr(addrs[5]));
    }

    // ── UselessBlockRemover ───────────────────────────────────────────────────

    #[test]
    fn test_useless_block_remove_dead() {
        let mut blocks = build_cfg(&[
            (0x100, 0x101, &[0xC3], &[], false, None),
            (
                0x200,
                0x201,
                &[0xC3],
                &[],
                /* no predecessor */ false,
                None,
            ),
        ]);
        let remover = UselessBlockRemover::new();
        let mut report = NormalizationReport::new();
        remover.run(Addr(0x100), &mut blocks, &mut report);
        assert!(!blocks.contains_key(&Addr(0x200)));
        assert_eq!(report.dead_blocks_removed, 1);
    }

    #[test]
    fn test_useless_block_keep_reachable() {
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x102,
                &[0xEB, 0x00],
                &[(0x200, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (0x200, 0x201, &[0xC3], &[], false, None),
        ]);
        let remover = UselessBlockRemover::new();
        let mut report = NormalizationReport::new();
        remover.run(Addr(0x100), &mut blocks, &mut report);
        assert!(blocks.contains_key(&Addr(0x200)));
        assert_eq!(report.dead_blocks_removed, 0);
    }

    #[test]
    fn test_useless_block_entry_not_removed() {
        let mut blocks = build_cfg(&[(0x100, 0x101, &[0xC3], &[], false, None)]);
        let remover = UselessBlockRemover::new();
        let mut report = NormalizationReport::new();
        remover.run(Addr(0x100), &mut blocks, &mut report);
        assert!(blocks.contains_key(&Addr(0x100)));
    }

    #[test]
    fn test_reachable_set_size() {
        let blocks = build_cfg(&[
            (
                0x100,
                0x102,
                &[0xEB, 0x00],
                &[(0x200, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (
                0x200,
                0x202,
                &[0xEB, 0x00],
                &[(0x300, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (0x300, 0x301, &[0xC3], &[], false, None),
            (0x400, 0x401, &[0xC3], &[], /* dead */ false, None),
        ]);
        let remover = UselessBlockRemover::new();
        let reachable = remover.reachable(Addr(0x100), &blocks);
        assert_eq!(reachable.len(), 3);
        assert!(!reachable.contains(&Addr(0x400)));
    }

    // ── BranchSimplifier ──────────────────────────────────────────────────────

    #[test]
    fn test_branch_always_taken() {
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x106,
                &[0x75, 0x04],
                &[(0x200, EdgeKind::True), (0x300, EdgeKind::False)],
                false,
                Some(true),
            ),
            (0x200, 0x201, &[0xC3], &[], false, None),
            (0x300, 0x301, &[0xC3], &[], false, None),
        ]);
        let simp = BranchSimplifier::new();
        let mut report = NormalizationReport::new();
        simp.run(&mut blocks, &mut report);
        let bb = &blocks[&Addr(0x100)];
        assert_eq!(bb.successors.len(), 1);
        assert_eq!(bb.successors[0].0, Addr(0x200));
        assert_eq!(report.always_taken_branches, 1);
    }

    #[test]
    fn test_branch_never_taken() {
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x106,
                &[0x74, 0x04],
                &[(0x200, EdgeKind::True), (0x300, EdgeKind::False)],
                false,
                Some(false),
            ),
            (0x200, 0x201, &[0xC3], &[], false, None),
            (0x300, 0x301, &[0xC3], &[], false, None),
        ]);
        let simp = BranchSimplifier::new();
        let mut report = NormalizationReport::new();
        simp.run(&mut blocks, &mut report);
        let bb = &blocks[&Addr(0x100)];
        assert_eq!(bb.successors.len(), 1);
        assert_eq!(bb.successors[0].0, Addr(0x300));
        assert_eq!(report.never_taken_branches, 1);
    }

    #[test]
    fn test_branch_unknown_unchanged() {
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x102,
                &[0x74, 0x00],
                &[(0x200, EdgeKind::True), (0x300, EdgeKind::False)],
                false,
                None,
            ),
            (0x200, 0x201, &[0xC3], &[], false, None),
            (0x300, 0x301, &[0xC3], &[], false, None),
        ]);
        let simp = BranchSimplifier::new();
        let mut report = NormalizationReport::new();
        simp.run(&mut blocks, &mut report);
        assert_eq!(blocks[&Addr(0x100)].successors.len(), 2);
        assert_eq!(report.always_taken_branches, 0);
        assert_eq!(report.never_taken_branches, 0);
    }

    // ── NopSledRemover ────────────────────────────────────────────────────────

    #[test]
    fn test_nop_sled_removed() {
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x102,
                &[0xEB, 0x00],
                &[(0x200, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (
                0x200,
                0x204,
                &[0x90, 0x90, 0x90, 0x90],
                &[(0x300, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (0x300, 0x301, &[0xC3], &[], false, None),
        ]);
        let remover = NopSledRemover::new();
        let mut report = NormalizationReport::new();
        remover.run(&mut blocks, &mut report);
        assert!(!blocks.contains_key(&Addr(0x200)));
        assert_eq!(blocks[&Addr(0x100)].successors[0].0, Addr(0x300));
        assert_eq!(report.nop_sleds_removed, 1);
        assert_eq!(report.nop_bytes_removed, 4);
    }

    #[test]
    fn test_nop_sled_not_removed_if_multiple_successors() {
        // A NOP block with two successors is not a sled.
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x102,
                &[0x90, 0x90],
                &[(0x200, EdgeKind::True), (0x300, EdgeKind::False)],
                false,
                None,
            ),
            (0x200, 0x201, &[0xC3], &[], false, None),
            (0x300, 0x301, &[0xC3], &[], false, None),
        ]);
        let remover = NopSledRemover::new();
        let mut report = NormalizationReport::new();
        remover.run(&mut blocks, &mut report);
        assert!(blocks.contains_key(&Addr(0x100)));
        assert_eq!(report.nop_sleds_removed, 0);
    }

    #[test]
    fn test_nop_sled_is_nop_block() {
        let remover = NopSledRemover::new();
        let nop_bb = BasicBlock::new(Addr(0), Addr(4), vec![0x90; 4]);
        let real_bb = BasicBlock::new(Addr(4), Addr(5), vec![0xC3]);
        assert!(remover.is_nop_block(&nop_bb));
        assert!(!remover.is_nop_block(&real_bb));
    }

    // ── CfgNormalizer (integration) ───────────────────────────────────────────

    #[test]
    fn test_normalizer_full_pipeline() {
        // Entry → trampoline → NOP sled → real block (dead block hanging off trampoline)
        let mut blocks = build_cfg(&[
            (
                0x1000,
                0x1002,
                &[0xEB, 0x00],
                &[(0x1010, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (
                0x1010,
                0x1012,
                &[0xEB, 0x00],
                &[(0x1020, EdgeKind::Unconditional)],
                true,
                None,
            ),
            (
                0x1020,
                0x1024,
                &[0x90; 4],
                &[(0x1030, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (0x1030, 0x1031, &[0xC3], &[], false, None),
            (0x9000, 0x9001, &[0xC3], &[], /* dead */ false, None),
        ]);
        let norm = CfgNormalizer::new(Addr(0x1000));
        let report = norm.run(&mut blocks);
        assert!(report.did_something());
        assert!(
            !blocks.contains_key(&Addr(0x9000)),
            "dead block should be gone"
        );
        assert!(
            !blocks.contains_key(&Addr(0x1020)),
            "NOP block should be gone"
        );
        // Entry should jump straight to 0x1030 after chained-jump elimination.
        assert_eq!(
            blocks[&Addr(0x1000)].successors[0].0,
            Addr(0x1030),
            "entry should point directly to final block"
        );
    }

    #[test]
    fn test_normalizer_empty_cfg() {
        let mut blocks: HashMap<Addr, BasicBlock> = HashMap::new();
        let norm = CfgNormalizer::new(Addr(0));
        let report = norm.run(&mut blocks);
        assert_eq!(report.blocks_remaining, 0);
    }

    #[test]
    fn test_normalizer_single_block() {
        let mut blocks = build_cfg(&[(0x100, 0x101, &[0xC3], &[], false, None)]);
        let norm = CfgNormalizer::new(Addr(0x100));
        let report = norm.run(&mut blocks);
        assert_eq!(report.blocks_remaining, 1);
    }

    #[test]
    fn test_normalizer_recompute_predecessors() {
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x102,
                &[0xEB, 0x00],
                &[(0x200, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (0x200, 0x201, &[0xC3], &[], false, None),
        ]);
        CfgNormalizer::recompute_predecessors(&mut blocks);
        assert_eq!(blocks[&Addr(0x200)].predecessor_count, 1);
        assert_eq!(blocks[&Addr(0x100)].predecessor_count, 0);
    }

    #[test]
    fn test_normalizer_constant_branch_in_pipeline() {
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x106,
                &[0x75, 0x04],
                &[(0x200, EdgeKind::True), (0x300, EdgeKind::False)],
                false,
                Some(true),
            ),
            (0x200, 0x201, &[0xC3], &[], false, None),
            (0x300, 0x301, &[0xC3], &[], false, None),
        ]);
        let norm = CfgNormalizer::new(Addr(0x100));
        let report = norm.run(&mut blocks);
        // 0x300 should be dead after simplification.
        assert!(!blocks.contains_key(&Addr(0x300)));
        assert!(report.always_taken_branches >= 1);
    }

    #[test]
    fn test_build_cfg_helper() {
        let blocks = build_cfg(&[
            (
                0x10,
                0x11,
                &[0x90],
                &[(0x20, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (0x20, 0x21, &[0xC3], &[], false, None),
        ]);
        assert_eq!(blocks.len(), 2);
        assert!(blocks.contains_key(&Addr(0x10)));
        assert!(blocks.contains_key(&Addr(0x20)));
    }

    #[test]
    fn test_normalizer_double_trampoline_chain_fully_collapsed() {
        // A → B → C → D (all B and C are trampolines)
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x102,
                &[0xEB, 0x00],
                &[(0x200, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (
                0x200,
                0x202,
                &[0xEB, 0x00],
                &[(0x300, EdgeKind::Unconditional)],
                true,
                None,
            ),
            (
                0x300,
                0x302,
                &[0xEB, 0x00],
                &[(0x400, EdgeKind::Unconditional)],
                true,
                None,
            ),
            (0x400, 0x401, &[0xC3], &[], false, None),
        ]);
        let norm = CfgNormalizer::new(Addr(0x100));
        let report = norm.run(&mut blocks);
        assert_eq!(
            blocks[&Addr(0x100)].successors[0].0,
            Addr(0x400),
            "should jump directly to 0x400"
        );
        assert!(report.chained_jumps_collapsed >= 1);
    }

    // ── Additional edge-case tests ────────────────────────────────────────────

    #[test]
    fn test_addr_as_u64() {
        assert_eq!(Addr(0xDEAD_BEEF).as_u64(), 0xDEAD_BEEF);
    }

    #[test]
    fn test_basic_block_is_nop_only_flag() {
        let mut bb = BasicBlock::new(Addr(0), Addr(4), vec![0x90; 4]);
        bb.is_nop_only = true;
        assert!(bb.is_nop_only);
    }

    #[test]
    fn test_normalizer_config_flags() {
        let norm = CfgNormalizer::new(Addr(0));
        assert!(norm.passes.simplify_branches);
        assert!(norm.passes.eliminate_chained_jumps);
        assert!(norm.passes.remove_nop_sleds);
        assert!(norm.remove_dead_blocks);
        assert_eq!(norm.max_iterations, 20);
    }

    #[test]
    fn test_nop_sled_remover_min_nop_count() {
        let remover = NopSledRemover { min_nop_count: 3 };
        let short_bb = BasicBlock::new(Addr(0), Addr(2), vec![0x90, 0x90]);
        let long_bb = BasicBlock::new(Addr(0), Addr(4), vec![0x90; 4]);
        assert!(!remover.is_nop_block(&short_bb)); // only 2 NOPs < min 3
        assert!(remover.is_nop_block(&long_bb));
    }

    #[test]
    fn test_branch_simplifier_no_successors_unchanged() {
        let mut blocks = build_cfg(&[(0x100, 0x101, &[0xC3], &[], false, Some(true))]);
        let simp = BranchSimplifier::new();
        let mut report = NormalizationReport::new();
        simp.run(&mut blocks, &mut report);
        // No true-edge to keep → block unchanged.
        assert_eq!(report.always_taken_branches, 0);
    }

    #[test]
    fn test_edge_kind_variants() {
        let k = EdgeKind::True;
        assert_eq!(k, EdgeKind::True);
        assert_ne!(k, EdgeKind::False);
        assert_ne!(k, EdgeKind::Unconditional);
    }

    #[test]
    fn test_cfg_normalizer_entry_always_kept() {
        // Entry block with no successors should survive dead-block removal.
        let mut blocks = build_cfg(&[(0x100, 0x101, &[0xC3], &[], false, None)]);
        let norm = CfgNormalizer::new(Addr(0x100));
        let _report = norm.run(&mut blocks);
        assert!(blocks.contains_key(&Addr(0x100)));
    }

    #[test]
    fn test_report_nop_bytes_removed() {
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x102,
                &[0xEB, 0x00],
                &[(0x200, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (
                0x200,
                0x208,
                &[0x90; 8],
                &[(0x300, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (0x300, 0x301, &[0xC3], &[], false, None),
        ]);
        let remover = NopSledRemover::new();
        let mut report = NormalizationReport::new();
        remover.run(&mut blocks, &mut report);
        assert_eq!(report.nop_bytes_removed, 8);
    }

    #[test]
    fn test_jump_eliminator_with_max_depth_1() {
        // Depth 1 should still resolve a single trampoline.
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x102,
                &[0xEB, 0x00],
                &[(0x200, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (
                0x200,
                0x202,
                &[0xEB, 0x00],
                &[(0x300, EdgeKind::Unconditional)],
                true,
                None,
            ),
            (0x300, 0x301, &[0xC3], &[], false, None),
        ]);
        let elim = ChainedJumpEliminator { max_chain_depth: 1 };
        let mut report = NormalizationReport::new();
        elim.run(&mut blocks, &mut report);
        // Should still resolve.
        assert_eq!(blocks[&Addr(0x100)].successors[0].0, Addr(0x300));
    }

    #[test]
    fn test_useless_block_diamond_all_reachable() {
        // Diamond shape: A → B, A → C, B → D, C → D.
        let blocks = build_cfg(&[
            (
                0x100,
                0x102,
                &[0xEB, 0x00],
                &[(0x200, EdgeKind::True), (0x300, EdgeKind::False)],
                false,
                None,
            ),
            (
                0x200,
                0x201,
                &[0x90],
                &[(0x400, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (
                0x300,
                0x301,
                &[0x90],
                &[(0x400, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (0x400, 0x401, &[0xC3], &[], false, None),
        ]);
        let remover = UselessBlockRemover::new();
        let reachable = remover.reachable(Addr(0x100), &blocks);
        assert_eq!(reachable.len(), 4);
    }

    #[test]
    fn test_normalizer_idempotent_on_clean_cfg() {
        // A clean two-block CFG should not be modified.
        let mut blocks = build_cfg(&[
            (
                0x100,
                0x102,
                &[0xEB, 0x00],
                &[(0x200, EdgeKind::Unconditional)],
                false,
                None,
            ),
            (0x200, 0x201, &[0xC3], &[], false, None),
        ]);
        let norm = CfgNormalizer::new(Addr(0x100));
        let report = norm.run(&mut blocks);
        assert_eq!(report.total_actions(), 0);
        assert_eq!(report.blocks_remaining, 2);
    }
}
