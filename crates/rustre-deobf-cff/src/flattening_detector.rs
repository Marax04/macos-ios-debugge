//! Control-flow flattening detector.
//!
//! Identifies whether a function has been obfuscated with OLLVM-style control-
//! flow flattening (CFF).  The detection pipeline:
//!
//! 1. Build a simplified CFG from basic-block edges.
//! 2. Locate a *dispatcher block* — a block with a large out-degree that tests
//!    a single "state variable" and branches to one of many successors.
//! 3. Score the function on several heuristics (out-degree, pre-dispatcher
//!    block count, state-variable usage density).
//! 4. Return a [`FlatteningReport`] with the score and the identified
//!    dispatcher / state-variable candidates.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// Basic CFG representation (input to the detector)
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block identifier (e.g., its start address or an index).
pub type BlockId = u64;

/// One basic block in the control-flow graph.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    /// Successor block IDs.
    pub successors: Vec<BlockId>,
    /// Predecessor block IDs.
    pub predecessors: Vec<BlockId>,
    /// Number of instructions in the block.
    pub instruction_count: usize,
    /// Number of assignments to the suspected state variable (0 if unknown).
    pub state_var_writes: usize,
    /// Number of comparisons against constant state values.
    pub state_var_reads: usize,
    /// True if this block contains only a switch/indirect-branch and no other
    /// real work.
    pub is_pure_dispatch: bool,
}

impl BasicBlock {
    #[must_use]
    pub const fn new(id: BlockId) -> Self {
        Self {
            id,
            successors: Vec::new(),
            predecessors: Vec::new(),
            instruction_count: 0,
            state_var_writes: 0,
            state_var_reads: 0,
            is_pure_dispatch: false,
        }
    }

    #[must_use]
    pub const fn out_degree(&self) -> usize { self.successors.len() }

    #[must_use]
    pub const fn in_degree(&self) -> usize { self.predecessors.len() }
}

// ─────────────────────────────────────────────────────────────────────────────
// SimpleCfg — a flat graph of BasicBlocks
// ─────────────────────────────────────────────────────────────────────────────

/// A simple control-flow graph used by the flattening detector.
#[derive(Debug, Default)]
pub struct SimpleCfg {
    pub blocks: HashMap<BlockId, BasicBlock>,
    pub entry: Option<BlockId>,
}

impl SimpleCfg {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn add_block(&mut self, block: BasicBlock) {
        self.blocks.insert(block.id, block);
    }

    pub fn add_edge(&mut self, from: BlockId, to: BlockId) {
        if let Some(b) = self.blocks.get_mut(&from) && !b.successors.contains(&to) {
            b.successors.push(to);
        }
        if let Some(b) = self.blocks.get_mut(&to) && !b.predecessors.contains(&from) {
            b.predecessors.push(from);
        }
    }

    #[must_use]
    pub fn block_count(&self) -> usize { self.blocks.len() }

    #[must_use]
    pub fn max_out_degree(&self) -> usize {
        self.blocks.values().map(BasicBlock::out_degree).max().unwrap_or(0)
    }

    /// Return the block with the highest out-degree.
    #[must_use]
    pub fn highest_out_degree_block(&self) -> Option<&BasicBlock> {
        // `blocks` is a HashMap: without a tie-break on the block id, two blocks
        // with the same out-degree would win arbitrarily and the reported block
        // would differ between runs on the same CFG.
        self.blocks
            .iter()
            .max_by(|a, b| {
                a.1.out_degree()
                    .cmp(&b.1.out_degree())
                    .then_with(|| b.0.cmp(a.0))
            })
            .map(|(_, b)| b)
    }

    /// BFS-reachable block count from `start`.
    #[must_use]
    pub fn reachable_from(&self, start: BlockId) -> usize {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id) { continue; }
            if let Some(b) = self.blocks.get(&id) {
                for &s in &b.successors { queue.push_back(s); }
            }
        }
        visited.len()
    }

    /// Compute dominators using a simple iterative algorithm.
    ///
    /// Returns a map `block → set of blocks that dominate it`.
    #[must_use]
    pub fn dominators(&self, entry: BlockId) -> HashMap<BlockId, HashSet<BlockId>> {
        let all: HashSet<BlockId> = self.blocks.keys().copied().collect();
        let mut dom: HashMap<BlockId, HashSet<BlockId>> = self
            .blocks
            .keys()
            .map(|&id| {
                let init = if id == entry {
                    let mut s = HashSet::new(); s.insert(id); s
                } else {
                    all.clone()
                };
                (id, init)
            })
            .collect();

        let mut changed = true;
        while changed {
            changed = false;
            for (&id, block) in &self.blocks {
                if id == entry { continue; }
                let mut new_dom: HashSet<BlockId> = if block.predecessors.is_empty() {
                    all.clone()
                } else {
                    block.predecessors.iter().fold(all.clone(), |acc, pred| {
                        if let Some(pd) = dom.get(pred) {
                            acc.intersection(pd).copied().collect()
                        } else {
                            acc
                        }
                    })
                };
                new_dom.insert(id);
                if let Some(old) = dom.get(&id) && *old != new_dom {
                    dom.insert(id, new_dom);
                    changed = true;
                }
            }
        }
        dom
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateVar candidate
// ─────────────────────────────────────────────────────────────────────────────

/// A suspected state variable used by the flattening dispatcher.
#[derive(Debug, Clone)]
pub struct StateVarCandidate {
    /// Symbolic name or register/stack-slot identifier.
    pub name: String,
    /// Number of write sites found.
    pub write_count: usize,
    /// Number of read sites found (comparisons).
    pub read_count: usize,
    /// Known constant values assigned to this variable.
    pub known_values: Vec<u64>,
    /// Confidence score 0.0–1.0.
    pub confidence: f64,
}

impl StateVarCandidate {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            write_count: 0,
            read_count: 0,
            known_values: Vec::new(),
            confidence: 0.0,
        }
    }

    pub fn compute_confidence(&mut self) {
        // Confidence is higher when both reads and writes are plentiful and
        // there are many distinct constant values.
        let rw = f64::from(u32::try_from(self.write_count + self.read_count).unwrap_or(u32::MAX));
        let vals = f64::from(u32::try_from(self.known_values.len()).unwrap_or(u32::MAX));
        // Use a saturating geometric-mean style score: each factor in [0,1]
        // and the final confidence is the square-root of their product so a
        // candidate with moderately strong evidence on both sides clears 0.5.
        let rw_factor = rw / (rw + 5.0);
        let val_factor = vals / (vals + 1.0);
        self.confidence = (rw_factor * val_factor).sqrt().min(1.0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DispatcherBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A block identified as the CFF dispatcher.
#[derive(Debug, Clone)]
pub struct DispatcherBlock {
    pub block_id: BlockId,
    /// Successor blocks (the "real" basic blocks that got flattened).
    pub targets: Vec<BlockId>,
    /// Number of dispatch arms.
    pub arm_count: usize,
    /// Does this block contain only branching code (no real computation)?
    pub is_pure: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// CffScheme — which CFF variant was detected
// ─────────────────────────────────────────────────────────────────────────────

/// The flavour of control-flow flattening detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CffScheme {
    /// Classic OLLVM: single dispatcher block, loop back from all blocks.
    OllvmClassic,
    /// Multiple dispatcher blocks (nested CFF).
    MultiDispatcher,
    /// State variable is obfuscated with MBA expressions.
    MbaObfuscated,
    /// Dispatcher uses an indirect branch through a jump table.
    JumpTableDispatcher,
    /// Unable to classify.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// FlatteningScore
// ─────────────────────────────────────────────────────────────────────────────

/// Numeric scoring of how likely a function is CFF-obfuscated.
#[derive(Debug, Clone, Default)]
pub struct FlatteningScore {
    /// Raw score 0.0–100.0.
    pub score: f64,
    /// Component: max out-degree of any block (normalised).
    pub out_degree_score: f64,
    /// Component: fraction of blocks that are "pre-dispatcher" (return to dispatcher).
    pub back_edge_score: f64,
    /// Component: state-variable usage density.
    pub state_var_score: f64,
    /// Component: presence of a pure-dispatch block.
    pub pure_dispatch_score: f64,
    /// Number of blocks in the function.
    pub block_count: usize,
    /// Maximum out-degree observed.
    pub max_out_degree: usize,
}

impl FlatteningScore {
    /// Return `true` if the score exceeds the detection threshold (≥50.0).
    #[must_use]
    pub const fn is_flattened(&self) -> bool { self.score >= 50.0 }

    /// Classification label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        if self.score < 20.0 {
            "clean"
        } else if self.score < 50.0 {
            "suspicious"
        } else if self.score < 75.0 {
            "likely_cff"
        } else {
            "confirmed_cff"
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlatteningReport — full detection result
// ─────────────────────────────────────────────────────────────────────────────

/// Full result of running the flattening detector on one function.
#[derive(Debug, Clone)]
pub struct FlatteningReport {
    pub score: FlatteningScore,
    pub scheme: CffScheme,
    pub dispatchers: Vec<DispatcherBlock>,
    pub state_vars: Vec<StateVarCandidate>,
    /// Pre-dispatcher blocks (those that end by looping back to the dispatcher).
    pub pre_dispatcher_blocks: Vec<BlockId>,
    /// Blocks that are never reached from the dispatcher (dead/irrelevant).
    pub unreachable_blocks: Vec<BlockId>,
}

impl FlatteningReport {
    #[must_use]
    pub const fn is_obfuscated(&self) -> bool { self.score.is_flattened() }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlatteningDetector
// ─────────────────────────────────────────────────────────────────────────────

/// The main detector.  Analyse a [`SimpleCfg`] and produce a [`FlatteningReport`].
#[derive(Debug, Default)]
pub struct FlatteningDetector {
    /// Minimum out-degree of a block to be considered a dispatcher candidate.
    pub dispatcher_min_outdegree: usize,
    /// Minimum block count to even bother analysing.
    pub min_block_count: usize,
}

impl FlatteningDetector {
    /// Create a detector with default thresholds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dispatcher_min_outdegree: 3,
            min_block_count: 5,
        }
    }

    /// Analyse a CFG and return a report.
    #[must_use]
    pub fn analyse(&self, cfg: &SimpleCfg) -> FlatteningReport {
        let block_count = cfg.block_count();
        let mut score = FlatteningScore { block_count, ..Default::default() };

        if block_count < self.min_block_count {
            return FlatteningReport {
                score,
                scheme: CffScheme::Unknown,
                dispatchers: vec![],
                state_vars: vec![],
                pre_dispatcher_blocks: vec![],
                unreachable_blocks: vec![],
            };
        }

        // ── Step 1: find dispatcher candidates ──────────────────────────────
        let dispatchers = Self::find_dispatchers(self.dispatcher_min_outdegree, cfg);
        let max_od = cfg.max_out_degree();
        score.max_out_degree = max_od;

        // Out-degree score: saturates at out-degree 16
        score.out_degree_score = ((f64::from(u32::try_from(max_od).unwrap_or(u32::MAX)) - 2.0).max(0.0) / 14.0 * 40.0).min(40.0);

        // Pure-dispatch block bonus
        let has_pure = cfg.blocks.values().any(|b| b.is_pure_dispatch);
        score.pure_dispatch_score = if has_pure { 15.0 } else { 0.0 };

        // ── Step 2: back-edge (pre-dispatcher) detection ─────────────────────
        let pre_dispatcher_blocks = dispatchers
            .first()
            .map_or_else(Vec::new, |dispatcher| {
                Self::find_pre_dispatcher_blocks(cfg, dispatcher.block_id)
            });
        let back_edge_ratio = f64::from(u32::try_from(pre_dispatcher_blocks.len()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(block_count).unwrap_or(1));
        score.back_edge_score = (back_edge_ratio * 30.0).min(30.0);

        // ── Step 3: state-variable score ─────────────────────────────────────
        let total_svw: usize = cfg.blocks.values().map(|b| b.state_var_writes).sum();
        let total_sv_reads: usize = cfg.blocks.values().map(|b| b.state_var_reads).sum();
        let sv_density = f64::from(u32::try_from(total_svw + total_sv_reads).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(block_count).unwrap_or(1));
        score.state_var_score = (sv_density * 5.0).min(15.0);

        score.score = score.out_degree_score
            + score.pure_dispatch_score
            + score.back_edge_score
            + score.state_var_score;

        // ── Step 4: scheme classification ────────────────────────────────────
        let scheme = Self::classify_scheme(&dispatchers);

        // ── Step 5: unreachable blocks ───────────────────────────────────────
        let unreachable_blocks = cfg.entry.map_or_else(Vec::new, |entry| {
            let reachable: HashSet<BlockId> = {
                let mut visited = HashSet::new();
                let mut queue = VecDeque::new();
                queue.push_back(entry);
                while let Some(id) = queue.pop_front() {
                    if !visited.insert(id) { continue; }
                    if let Some(b) = cfg.blocks.get(&id) {
                        for &s in &b.successors { queue.push_back(s); }
                    }
                }
                visited
            };
            cfg.blocks
                .keys()
                .filter(|id| !reachable.contains(*id))
                .copied()
                .collect()
        });

        // ── Step 6: state-var candidates ─────────────────────────────────────
        let state_vars = Self::extract_state_var_candidates(cfg);

        FlatteningReport {
            score,
            scheme,
            dispatchers,
            state_vars,
            pre_dispatcher_blocks,
            unreachable_blocks,
        }
    }

    // ── Private helpers (associated functions, no &self needed) ──────────────

    fn find_dispatchers(dispatcher_min_outdegree: usize, cfg: &SimpleCfg) -> Vec<DispatcherBlock> {
        let mut result = Vec::new();
        for block in cfg.blocks.values() {
            if block.out_degree() >= dispatcher_min_outdegree {
                result.push(DispatcherBlock {
                    block_id: block.id,
                    targets: block.successors.clone(),
                    arm_count: block.out_degree(),
                    is_pure: block.is_pure_dispatch,
                });
            }
        }
        // Sort by arm_count descending so the main dispatcher is first.
        result.sort_by_key(|b| std::cmp::Reverse(b.arm_count));
        result
    }

    fn find_pre_dispatcher_blocks(cfg: &SimpleCfg, dispatcher_id: BlockId) -> Vec<BlockId> {
        // The function entry feeds the dispatcher once on the way in; that is
        // not a "pre-dispatcher" handler block — only blocks that loop back
        // from inside the dispatch body count.
        cfg.blocks
            .values()
            .filter(|b| {
                b.id != dispatcher_id
                    && Some(b.id) != cfg.entry
                    && b.successors.contains(&dispatcher_id)
            })
            .map(|b| b.id)
            .collect()
    }

    fn classify_scheme(dispatchers: &[DispatcherBlock]) -> CffScheme {
        match dispatchers.len() {
            0 => CffScheme::Unknown,
            1 => {
                if dispatchers[0].arm_count > 20 {
                    CffScheme::JumpTableDispatcher
                } else {
                    CffScheme::OllvmClassic
                }
            }
            _ => CffScheme::MultiDispatcher,
        }
    }

    fn extract_state_var_candidates(cfg: &SimpleCfg) -> Vec<StateVarCandidate> {
        let total_writes: usize = cfg.blocks.values().map(|b| b.state_var_writes).sum();
        let total_reads: usize  = cfg.blocks.values().map(|b| b.state_var_reads).sum();

        if total_writes == 0 && total_reads == 0 {
            return vec![];
        }

        let mut candidate = StateVarCandidate::new("sv0");
        candidate.write_count = total_writes;
        candidate.read_count  = total_reads;
        candidate.compute_confidence();
        vec![candidate]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_flat_cfg() -> SimpleCfg {
        let mut cfg = SimpleCfg::new();
        cfg.entry = Some(0);

        // Entry block
        let mut entry = BasicBlock::new(0);
        entry.instruction_count = 5;
        entry.state_var_writes = 1;
        cfg.add_block(entry);

        // Dispatcher block (pure dispatch, out-degree 5)
        let mut disp = BasicBlock::new(1);
        disp.instruction_count = 2;
        disp.is_pure_dispatch = true;
        disp.state_var_reads = 1;
        cfg.add_block(disp);

        // 5 "real" blocks that all loop back to dispatcher
        for i in 2..7u64 {
            let mut b = BasicBlock::new(i);
            b.instruction_count = 8;
            b.state_var_writes = 1;
            b.state_var_reads = 1;
            cfg.add_block(b);
        }

        // Exit block
        let exit = BasicBlock::new(7);
        cfg.add_block(exit);

        cfg.add_edge(0, 1); // entry → dispatcher
        for i in 2..7u64 {
            cfg.add_edge(1, i);  // dispatcher → real blocks
            cfg.add_edge(i, 1);  // real blocks → dispatcher (back edges)
        }
        cfg.add_edge(1, 7); // dispatcher → exit

        cfg
    }

    #[test]
    fn test_flattened_function_detected() {
        let cfg = make_flat_cfg();
        let detector = FlatteningDetector::new();
        let report = detector.analyse(&cfg);
        assert!(report.is_obfuscated(), "score = {:.1}", report.score.score);
        assert_eq!(report.scheme, CffScheme::OllvmClassic);
    }

    #[test]
    fn test_clean_function_not_flagged() {
        let mut cfg = SimpleCfg::new();
        cfg.entry = Some(0);
        for i in 0..4u64 {
            let mut b = BasicBlock::new(i);
            b.instruction_count = 10;
            cfg.add_block(b);
        }
        cfg.add_edge(0, 1); cfg.add_edge(1, 2); cfg.add_edge(2, 3);

        let detector = FlatteningDetector::new();
        let report = detector.analyse(&cfg);
        assert!(!report.is_obfuscated(), "score = {:.1}", report.score.score);
    }

    #[test]
    fn test_dispatcher_found() {
        let cfg = make_flat_cfg();
        let detector = FlatteningDetector::new();
        let report = detector.analyse(&cfg);
        assert!(!report.dispatchers.is_empty());
        assert_eq!(report.dispatchers[0].block_id, 1);
    }

    #[test]
    fn test_pre_dispatcher_blocks() {
        let cfg = make_flat_cfg();
        let detector = FlatteningDetector::new();
        let report = detector.analyse(&cfg);
        // Blocks 2..6 should all be pre-dispatcher (they loop back to block 1)
        assert_eq!(report.pre_dispatcher_blocks.len(), 5);
    }

    #[test]
    fn test_score_label() {
        assert_eq!(FlatteningScore { score:  0.0, ..Default::default() }.label(), "clean");
        assert_eq!(FlatteningScore { score: 25.0, ..Default::default() }.label(), "suspicious");
        assert_eq!(FlatteningScore { score: 55.0, ..Default::default() }.label(), "likely_cff");
        assert_eq!(FlatteningScore { score: 80.0, ..Default::default() }.label(), "confirmed_cff");
    }

    #[test]
    fn test_state_var_candidate() {
        let mut sv = StateVarCandidate::new("var_10");
        sv.write_count = 8;
        sv.read_count  = 12;
        sv.known_values = vec![0, 1, 2, 3, 4];
        sv.compute_confidence();
        assert!(sv.confidence > 0.5);
    }

    #[test]
    fn test_too_small_function() {
        let mut cfg = SimpleCfg::new();
        cfg.entry = Some(0);
        cfg.add_block(BasicBlock::new(0));
        cfg.add_block(BasicBlock::new(1));
        cfg.add_edge(0, 1);

        let detector = FlatteningDetector::new();
        let report = detector.analyse(&cfg);
        assert!(!report.is_obfuscated());
    }
}
